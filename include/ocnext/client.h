#ifndef OCNEXT_CLIENT_H
#define OCNEXT_CLIENT_H

#include "ocnext/bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

enum ocnext_client_result {
    OCNEXT_CLIENT_OK = 0,
    OCNEXT_CLIENT_ARGUMENT = -2001,
    OCNEXT_CLIENT_UNAVAILABLE = -2002,
    OCNEXT_CLIENT_PEER = -2003,
    OCNEXT_CLIENT_TIMEOUT = -2004,
    OCNEXT_CLIENT_IO = -2005,
    OCNEXT_CLIENT_PROTOCOL = -2006,
    OCNEXT_CLIENT_ALLOCATION = -2007,
    OCNEXT_CLIENT_CLOSED = -2008,
    OCNEXT_CLIENT_CAPABILITY = -2009
};

struct ocnext_client;
struct ocnext_client_handle { uint64_t id; uint32_t generation, type; };
struct ocnext_client_info { uint64_t session_id, capabilities; uint32_t generation; uint16_t wire_minor; };

/* Hosted POSIX same-UID transport, no root privileges or remote sockets.
 * timeout_ms is 10..60000 and bounds the whole connect+HELLO or each exchange.
 * One context must be serialized by its caller. No automatic reconnect/replay.
 * Semantic failures return the broker's -1001..-1015 status; local failures use
 * -2001..-2009. Transport/protocol failure closes the context until destruction.
 * Native output buffers/handles change only after a fully validated success. */
OCNEXT_API int ocnext_client_open(const char *socket_path, uint32_t timeout_ms, struct ocnext_client **out);
OCNEXT_API void ocnext_client_close(struct ocnext_client *);
OCNEXT_API int ocnext_client_get_info(const struct ocnext_client *, struct ocnext_client_info *);
OCNEXT_API int ocnext_client_buffer_register(struct ocnext_client *, uint64_t bytes, uint32_t usage,
                                            struct ocnext_client_handle *);
OCNEXT_API int ocnext_client_buffer_release(struct ocnext_client *, struct ocnext_client_handle);
OCNEXT_API int ocnext_client_buffer_read(struct ocnext_client *, struct ocnext_client_handle,
                                        uint64_t offset, void *destination, size_t bytes);
OCNEXT_API int ocnext_client_buffer_write(struct ocnext_client *, struct ocnext_client_handle,
                                         uint64_t offset, const void *source, size_t bytes);
OCNEXT_API int ocnext_client_buffer_copy(struct ocnext_client *, struct ocnext_client_handle source,
                                        uint64_t source_offset, struct ocnext_client_handle destination,
                                        uint64_t destination_offset, size_t bytes);
OCNEXT_API int ocnext_client_session_reset(struct ocnext_client *);
OCNEXT_API int ocnext_client_gpu_probe(struct ocnext_client *);
OCNEXT_API const char *ocnext_client_result_string(int);

#ifdef __cplusplus
}
#endif
#endif
