#ifndef OCNEXT_PROXY_H
#define OCNEXT_PROXY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_PROXY_ABI_VERSION 1u
#define OCNEXT_PROXY_REQUEST_BYTES 64u
#define OCNEXT_PROXY_REPLY_BYTES 36u
#define OCNEXT_PROXY_PAYLOAD_BYTES 56u
#define OCNEXT_PROXY_MAX_TRANSFER 4096u
#define OCNEXT_PROXY_MAX_FRAME (OCNEXT_PROXY_REQUEST_BYTES + OCNEXT_PROXY_MAX_TRANSFER)
#define OCNEXT_PROXY_MAX_REPLY (OCNEXT_PROXY_REPLY_BYTES + OCNEXT_PROXY_MAX_TRANSFER)
#define OCNEXT_PROXY_MAX_BATCH 8u
#define OCNEXT_PROXY_MAX_STREAM_INPUT 65536u
#define OCNEXT_PROXY_MAX_RAM UINT64_C(1073741824)

#define OCNEXT_PROXY_REQ_NOP UINT32_C(0x00aa55ff)
#define OCNEXT_PROXY_REQ_PROXY UINT32_C(0x01aa55ff)
#define OCNEXT_PROXY_REQ_MEMREAD UINT32_C(0x02aa55ff)
#define OCNEXT_PROXY_REQ_MEMWRITE UINT32_C(0x03aa55ff)
#define OCNEXT_PROXY_P_NOP UINT64_C(0x000)
#define OCNEXT_PROXY_P_SET_EXC_GUARD UINT64_C(0x007)
#define OCNEXT_PROXY_P_GET_EXC_COUNT UINT64_C(0x008)
#define OCNEXT_PROXY_P_WRITE64 UINT64_C(0x100)
#define OCNEXT_PROXY_P_WRITE32 UINT64_C(0x101)
#define OCNEXT_PROXY_P_WRITE16 UINT64_C(0x102)
#define OCNEXT_PROXY_P_WRITE8 UINT64_C(0x103)
#define OCNEXT_PROXY_P_READ64 UINT64_C(0x104)
#define OCNEXT_PROXY_P_READ32 UINT64_C(0x105)
#define OCNEXT_PROXY_P_READ16 UINT64_C(0x106)
#define OCNEXT_PROXY_P_READ8 UINT64_C(0x107)
#define OCNEXT_PROXY_GUARD_RETURN 3u

#define OCNEXT_PROXY_CAP_CONTROL 1u
#define OCNEXT_PROXY_CAP_RAM_READ 2u
#define OCNEXT_PROXY_CAP_RAM_WRITE 4u
#define OCNEXT_PROXY_CAP_RECOVERY 8u
#define OCNEXT_PROXY_CAP_ALL 15u

/* Exact upstream outer status values; checksum is integrity, not authentication. */
enum ocnext_proxy_wire_status {
    OCNEXT_PROXY_ST_OK = 0,
    OCNEXT_PROXY_ST_BADCMD = -1,
    OCNEXT_PROXY_ST_INVAL = -2,
    OCNEXT_PROXY_ST_XFRERR = -3,
    OCNEXT_PROXY_ST_CSUMERR = -4
};
enum ocnext_proxy_result {
    OCNEXT_PROXY_OK = 0,
    OCNEXT_PROXY_ARGUMENT = 1,
    OCNEXT_PROXY_INVALID_WIRE = 2,
    OCNEXT_PROXY_OUTPUT_TOO_SMALL = 3,
    OCNEXT_PROXY_WRONG_OWNER = 4,
    OCNEXT_PROXY_WRONG_SESSION = 5,
    OCNEXT_PROXY_STALE_GENERATION = 6,
    OCNEXT_PROXY_REPLAY = 7,
    OCNEXT_PROXY_BATCH_ABORTED = 8,
    OCNEXT_PROXY_CLOSED = 9,
    OCNEXT_PROXY_EXHAUSTED = 10,
    OCNEXT_PROXY_CAPABILITY = 11
};

/* Neither legacy proxy framing nor its ProxyRequest has a sequence/session/generation.
 * This native ticket is explicitly supplied by an authenticated OUTER transport.
 * Raw UART bytes cannot establish its authority. No outer wire/authentication
 * implementation is claimed here, and this is not an ONXT header extension.
 */
struct ocnext_proxy_ticket {
    uint64_t owner_id, session_id, sequence;
    uint32_t generation, reserved;
};
struct ocnext_proxy_request_view {
    uint32_t type;
    uint8_t payload[OCNEXT_PROXY_PAYLOAD_BYTES];
    const uint8_t *write_data;
    size_t write_bytes;
};
struct ocnext_proxy_reply_view {
    uint32_t type;
    int32_t status;
    uint8_t payload[24];
    const uint8_t *read_data;
    size_t read_bytes;
};

/* All buffers are native caller-owned readable/writable ranges, never guest
 * pointers. View outputs must be distinct from their borrowed frame. Pure codecs
 * have no allocation/libc dependency. Output unchanged on
 * rejection. Request bytes include MEMWRITE's declared data; MEMREAD reply bytes
 * include the exact expected read length. Disabled-checksum mode is unsupported.
 */
enum ocnext_proxy_result ocnext_proxy_checksum(const uint8_t *, size_t, uint32_t *);
enum ocnext_proxy_result ocnext_proxy_encode_request(uint32_t type,
    const uint8_t *payload, size_t payload_bytes, const uint8_t *write_data,
    size_t write_bytes, uint8_t *out, size_t capacity, size_t *written);
enum ocnext_proxy_result ocnext_proxy_parse_request(const uint8_t *, size_t,
                                                   struct ocnext_proxy_request_view *);
enum ocnext_proxy_result ocnext_proxy_parse_reply(const uint8_t *, size_t,
    uint32_t expected_type, size_t expected_read_bytes, struct ocnext_proxy_reply_view *);

struct ocnext_proxy_write {
    uint64_t address;
    const uint8_t *data;
    size_t bytes;
};
/* Trusted owned-RAM bus, stable during a dispatch. No MMIO or read side effects.
 * All callbacks return 1 on success and 0 on failure. probe/read transfer the
 * WHOLE range or fail. writev preflights ALL spans and
 * commits all, in supplied order (overlap allowed), or changes no byte. Native
 * context/backing is caller-owned; the proxy never casts a guest address.
 */
struct ocnext_proxy_bus {
    void *context;
    int (*probe)(void *, uint64_t, size_t, unsigned write);
    int (*read)(void *, uint64_t, uint8_t *, size_t);
    int (*writev)(void *, const struct ocnext_proxy_write *, size_t);
};
struct ocnext_proxy_session {
    struct ocnext_proxy_bus bus;
    uint64_t owner_id, session_id, last_sequence, ram_base, ram_bytes, fault_count;
    uint32_t generation, capabilities, guard, open;
};
struct ocnext_proxy_item {
    struct ocnext_proxy_ticket ticket;
    const uint8_t *request;
    size_t request_bytes;
    uint8_t *reply;
    size_t reply_capacity, reply_bytes;
};
/* Caller-owned scratch keeps large staging buffers off the EFI stack. Must be
 * distinct from session/items/input/output/backing; calls must be serialized. */
struct ocnext_proxy_workspace {
    uint8_t data[OCNEXT_PROXY_MAX_BATCH][OCNEXT_PROXY_MAX_TRANSFER];
    uint8_t replies[OCNEXT_PROXY_MAX_BATCH][OCNEXT_PROXY_MAX_REPLY];
    struct ocnext_proxy_write writes[OCNEXT_PROXY_MAX_BATCH];
    struct ocnext_proxy_request_view views[OCNEXT_PROXY_MAX_BATCH];
};

enum ocnext_proxy_result ocnext_proxy_session_init(struct ocnext_proxy_session *,
    const struct ocnext_proxy_bus *, uint64_t owner, uint64_t session,
    uint32_t generation, uint32_t capabilities, uint64_t ram_base, uint64_t ram_bytes);
/* Native, explicitly authorized recovery only: invalidate old tickets and reset
 * sequence/fault counters. Does not clear RAM, reboot a CPU/device or touch MMIO. */
enum ocnext_proxy_result ocnext_proxy_session_reset(struct ocnext_proxy_session *,
                                                  const struct ocnext_proxy_ticket *);
enum ocnext_proxy_result ocnext_proxy_session_close(struct ocnext_proxy_session *,
                                                  const struct ocnext_proxy_ticket *);
/* count1 dispatches the bounded subset; count2..8 accepts RAM WRITE commands only.
 * Parse/output/auth/replay rejection leaves session and replies unchanged.
 * Authorized semantic failures consume all supplied sequences, report exact
 * failing status and mark other batch entries XFRERR; no writes commit.
 * Native objects/frame/reply ranges must be valid and distinct from the session,
 * item array, workspace and bus backing; output ranges may not overlap each other.
 * Input frames may not overlap output ranges (including another batch item).
 * Reply capacities are bounded to MAX_REPLY. Successful writes invoke trusted
 * writev exactly once. reply_bytes updates only
 * when replies are actually produced. No UART/IRQ transport is connected.
 */
enum ocnext_proxy_result ocnext_proxy_dispatch_batch(struct ocnext_proxy_session *,
    struct ocnext_proxy_item *, size_t count, struct ocnext_proxy_workspace *);

enum ocnext_proxy_stream_result {
    OCNEXT_PROXY_STREAM_NEED_MORE = 0,
    OCNEXT_PROXY_STREAM_FRAME = 1,
    OCNEXT_PROXY_STREAM_LIMIT = 2,
    OCNEXT_PROXY_STREAM_ARGUMENT = 3
};
/* Native stream/input/output/size-output ranges must not overlap the stream or
 * each other. REQUEST receiver only. Read-reply trailing lengths need request context and
 * are handled by parse_reply, not guessed from a byte stream. Decoder resync does
 * not authenticate recovered frames; callers supply outer tickets explicitly.
 */
struct ocnext_proxy_stream {
    uint8_t bytes[OCNEXT_PROXY_MAX_FRAME];
    size_t used, expected;
    uint64_t discarded_bytes, checksum_errors;
    uint32_t ready, poisoned;
};
void ocnext_proxy_stream_init(struct ocnext_proxy_stream *);
/* Explicit partial/limit recovery; preserves diagnostics, not session authority. */
void ocnext_proxy_stream_reset(struct ocnext_proxy_stream *);
enum ocnext_proxy_stream_result ocnext_proxy_stream_push(struct ocnext_proxy_stream *,
    const uint8_t *, size_t, size_t *consumed);
enum ocnext_proxy_result ocnext_proxy_stream_take(struct ocnext_proxy_stream *,
                                                uint8_t *, size_t, size_t *written);

#ifdef __cplusplus
}
#endif
#endif
