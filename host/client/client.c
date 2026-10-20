#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ocnext/client.h"
#include "ocnext/broker.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

struct ocnext_client
{
    int fd;
    uint32_t timeout_ms;
    uint64_t next_request;
    struct ocnext_client_info info;
    uint8_t request[64 + 40 + OCNEXT_BROKER_MAX_TRANSFER];
    uint8_t response[OCNEXT_BROKER_DATA_RESPONSE_CAPACITY];
};

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | (uint64_t)get32(p + 4) << 32;
}
static void put32(uint8_t *p, uint32_t n)
{
    unsigned i;
    for (i = 0; i < 4; ++i)
        p[i] = (uint8_t)(n >> (8 * i));
}
static void put64(uint8_t *p, uint64_t n)
{
    put32(p, (uint32_t)n);
    put32(p + 4, (uint32_t)(n >> 32));
}
static void handle_bytes(uint8_t *p, struct ocnext_client_handle h)
{
    put64(p, h.id);
    put32(p + 8, h.generation);
    put32(p + 12, h.type);
}
static uint64_t now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int invalidate(struct ocnext_client *c, int result)
{
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
    return result;
}
static int wait_fd(int fd, short events, uint64_t deadline)
{
    for (;;)
    {
        struct pollfd p = {fd, events, 0};
        uint64_t now = now_ms(), left;
        int result;
        if (!now)
            return OCNEXT_CLIENT_IO;
        if (now >= deadline)
            return OCNEXT_CLIENT_TIMEOUT;
        left = deadline - now;
        result = poll(&p, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (result < 0 && errno == EINTR)
            continue;
        if (result == 0)
            return OCNEXT_CLIENT_TIMEOUT;
        if (result < 0)
            return OCNEXT_CLIENT_IO;
        if (p.revents & events)
            return 0;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL))
            return OCNEXT_CLIENT_IO;
    }
}
static int exact_io(int fd, uint8_t *data, size_t bytes, int sending, uint64_t deadline)
{
    size_t done = 0;
    while (done < bytes)
    {
        size_t chunk = bytes - done;
        ssize_t n;
        int result = wait_fd(fd, sending ? POLLOUT : POLLIN, deadline);
        if (result)
            return result;
        if (chunk > 4096)
            chunk = 4096;
        if (sending)
        {
#if defined(MSG_NOSIGNAL)
            n = send(fd, data + done, chunk, MSG_NOSIGNAL);
#else
            n = send(fd, data + done, chunk, 0);
#endif
        }
        else
            n = recv(fd, data + done, chunk, 0);
        if (n > 0)
            done += (size_t)n;
        else if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        else
            return OCNEXT_CLIENT_IO;
    }
    return 0;
}
static int peer_is_same_uid(int fd)
{
#if defined(__APPLE__) || defined(__FreeBSD__)
    uid_t uid;
    gid_t gid;
    return getpeereid(fd, &uid, &gid) == 0 && uid == geteuid();
#elif defined(__linux__)
    struct ucred value;
    socklen_t bytes = sizeof(value);
    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &value, &bytes) == 0 && bytes == sizeof(value) &&
           value.uid == geteuid();
#else
    (void)fd;
    return 0;
#endif
}
static int exchange(struct ocnext_client *c, uint16_t op, size_t body, size_t expected,
                    struct ocnext_bridge_view *view, uint64_t deadline)
{
    struct ocnext_bridge_header h;
    uint32_t bytes;
    int result;
    if (!c || !view)
        return OCNEXT_CLIENT_ARGUMENT;
    if (c->fd < 0)
        return OCNEXT_CLIENT_CLOSED;
    if (c->next_request == UINT64_MAX)
        return OCNEXT_CLIENT_ARGUMENT;
    if (!deadline)
    {
        uint64_t now = now_ms();
        if (!now)
            return invalidate(c, OCNEXT_CLIENT_IO);
        deadline = now + c->timeout_ms;
    }
    memset(&h, 0, sizeof(h));
    h.version_major = 1;
    h.version_minor = OCNEXT_BRIDGE_DATA_MINOR;
    h.operation = op;
    h.flags = OCNEXT_FLAG_REQUEST;
    h.total_size = (uint32_t)(64 + body);
    h.request_id = c->next_request++;
    h.session_id = c->info.session_id;
    h.generation = c->info.generation;
    if (op == OCNEXT_OP_HELLO)
        h.capability_mask = OCNEXT_BROKER_CAP_IMPLEMENTED;
    if (ocnext_bridge_encode_header(&h, c->request, sizeof(c->request)) != OCNEXT_OK)
        return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
    result = exact_io(c->fd, c->request, 64 + body, 1, deadline);
    if (!result)
        result = exact_io(c->fd, c->response, 64, 0, deadline);
    if (result)
        return invalidate(c, result);
    bytes = get32(c->response + 12);
    if (bytes < 72 || bytes > sizeof(c->response))
        return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
    result = exact_io(c->fd, c->response + 64, bytes - 64, 0, deadline);
    if (result)
        return invalidate(c, result);
    if (ocnext_bridge_parse(c->response, bytes, view) != OCNEXT_OK ||
        view->header.version_minor != 1 || view->header.operation != op ||
        view->header.flags != OCNEXT_FLAG_RESPONSE || view->header.request_id != h.request_id ||
        get32(view->payload) != 1 || get32(view->payload + 4) != 0 ||
        (op != OCNEXT_OP_HELLO && (view->header.session_id != c->info.session_id ||
                                   view->header.capability_mask != c->info.capabilities)))
        return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
    if (view->header.status)
    {
        if (view->header.status > -1001 || view->header.status < -1015 || view->payload_size != 8 ||
            (op != OCNEXT_OP_HELLO && view->header.generation != c->info.generation))
            return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
        return view->header.status;
    }
    if (view->payload_size != expected)
        return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
    if (op == OCNEXT_OP_HELLO)
    {
        uint64_t caps = view->header.capability_mask;
        if (!view->header.session_id || view->header.generation != 1 ||
            (caps & ~OCNEXT_BROKER_CAP_IMPLEMENTED) || get32(view->payload + 12) != 16)
            return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
        if ((caps & 11) != 11)
            return invalidate(c, OCNEXT_CLIENT_CAPABILITY);
        c->info.session_id = view->header.session_id;
        c->info.generation = 1;
        c->info.capabilities = caps;
        c->info.wire_minor = 1;
    }
    else if (op == OCNEXT_OP_DEVICE_RESET)
    {
        if (c->info.generation == UINT32_MAX || view->header.generation != c->info.generation + 1)
            return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
        c->info.generation = view->header.generation;
    }
    else if (view->header.generation != c->info.generation)
        return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
    return 0;
}
int ocnext_client_open(const char *path, uint32_t timeout_ms, struct ocnext_client **out)
{
    struct ocnext_client *c;
    struct sockaddr_un address;
    struct stat info;
    struct ocnext_bridge_view view;
    uint64_t deadline;
    int result, flags;
    if (!out)
        return OCNEXT_CLIENT_ARGUMENT;
    *out = NULL;
    if (!path || !path[0] || strlen(path) >= sizeof(address.sun_path) || timeout_ms < 10 ||
        timeout_ms > 60000 || geteuid() == 0)
        return OCNEXT_CLIENT_ARGUMENT;
    if (lstat(path, &info) || !S_ISSOCK(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & 0777) != 0600)
        return OCNEXT_CLIENT_PEER;
    c = calloc(1, sizeof(*c));
    if (!c)
        return OCNEXT_CLIENT_ALLOCATION;
    c->fd = -1;
    c->timeout_ms = timeout_ms;
    c->next_request = 1;
    deadline = now_ms();
    if (!deadline)
    {
        free(c);
        return OCNEXT_CLIENT_IO;
    }
    deadline += timeout_ms;
    c->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c->fd < 0)
    {
        free(c);
        return OCNEXT_CLIENT_IO;
    }
    flags = fcntl(c->fd, F_GETFL);
    if (flags < 0 || fcntl(c->fd, F_SETFL, flags | O_NONBLOCK) || fcntl(c->fd, F_SETFD, FD_CLOEXEC))
    {
        ocnext_client_close(c);
        return OCNEXT_CLIENT_IO;
    }
#if defined(SO_NOSIGPIPE)
    {
        int one = 1;
        if (setsockopt(c->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)))
        {
            ocnext_client_close(c);
            return OCNEXT_CLIENT_IO;
        }
    }
#elif !defined(MSG_NOSIGNAL)
    ocnext_client_close(c);
    return OCNEXT_CLIENT_UNAVAILABLE;
#endif
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    result = connect(c->fd, (struct sockaddr *)&address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS)
    {
        ocnext_client_close(c);
        return OCNEXT_CLIENT_IO;
    }
    if (result < 0)
    {
        int error = 0;
        socklen_t bytes = sizeof(error);
        result = wait_fd(c->fd, POLLOUT, deadline);
        if (result || getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &error, &bytes) || error)
        {
            ocnext_client_close(c);
            return result ? result : OCNEXT_CLIENT_IO;
        }
    }
    if (!peer_is_same_uid(c->fd))
    {
        ocnext_client_close(c);
        return OCNEXT_CLIENT_PEER;
    }
    put32(c->request + 64, 1);
    result = exchange(c, OCNEXT_OP_HELLO, 8, 32, &view, deadline);
    if (result)
    {
        ocnext_client_close(c);
        return result;
    }
    *out = c;
    return 0;
}
void ocnext_client_close(struct ocnext_client *c)
{
    if (c)
    {
        if (c->fd >= 0)
            close(c->fd);
        memset(c, 0, sizeof(*c));
        free(c);
    }
}
int ocnext_client_get_info(const struct ocnext_client *c, struct ocnext_client_info *out)
{
    if (!c || !out)
        return OCNEXT_CLIENT_ARGUMENT;
    if (c->fd < 0)
        return OCNEXT_CLIENT_CLOSED;
    *out = c->info;
    return 0;
}
static int prefix(struct ocnext_client *c, size_t bytes)
{
    if (!c)
        return OCNEXT_CLIENT_ARGUMENT;
    if (c->fd < 0)
        return OCNEXT_CLIENT_CLOSED;
    memset(c->request + 64, 0, bytes);
    put32(c->request + 64, 1);
    return 0;
}
int ocnext_client_buffer_register(struct ocnext_client *c, uint64_t bytes, uint32_t usage,
                                  struct ocnext_client_handle *out)
{
    struct ocnext_bridge_view v;
    int r;
    if (!out || !bytes || !usage || (usage & ~UINT32_C(3)))
        return OCNEXT_CLIENT_ARGUMENT;
    r = prefix(c, 32);
    if (r)
        return r;
    put32(c->request + 68, usage);
    put64(c->request + 72, bytes);
    put64(c->request + 80, 1);
    r = exchange(c, OCNEXT_OP_BUFFER_REGISTER, 32, 24, &v, 0);
    if (r)
        return r;
    if (!get64(v.payload + 8) || get32(v.payload + 20) != 1 || !get32(v.payload + 16))
        return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
    out->id = get64(v.payload + 8);
    out->generation = get32(v.payload + 16);
    out->type = 1;
    return 0;
}
int ocnext_client_buffer_release(struct ocnext_client *c, struct ocnext_client_handle handle)
{
    struct ocnext_bridge_view v;
    int r = prefix(c, 24);
    if (r)
        return r;
    handle_bytes(c->request + 72, handle);
    return exchange(c, OCNEXT_OP_BUFFER_RELEASE, 24, 8, &v, 0);
}
static int data_prepare(struct ocnext_client *c, struct ocnext_client_handle handle,
                        uint64_t offset, size_t bytes)
{
    int r;
    if (!bytes || bytes > OCNEXT_BROKER_MAX_TRANSFER)
        return OCNEXT_CLIENT_ARGUMENT;
    r = prefix(c, 40);
    if (r)
        return r;
    handle_bytes(c->request + 72, handle);
    put64(c->request + 88, offset);
    put64(c->request + 96, bytes);
    return 0;
}
int ocnext_client_buffer_read(struct ocnext_client *c, struct ocnext_client_handle h,
                              uint64_t offset, void *out, size_t bytes)
{
    struct ocnext_bridge_view v;
    int r;
    if (!out)
        return OCNEXT_CLIENT_ARGUMENT;
    r = data_prepare(c, h, offset, bytes);
    if (r)
        return r;
    r = exchange(c, OCNEXT_OP_BUFFER_READ, 40, 16 + bytes, &v, 0);
    if (r)
        return r;
    if (get64(v.payload + 8) != bytes)
        return invalidate(c, OCNEXT_CLIENT_PROTOCOL);
    memcpy(out, v.payload + 16, bytes);
    return 0;
}
int ocnext_client_buffer_write(struct ocnext_client *c, struct ocnext_client_handle h,
                               uint64_t offset, const void *data, size_t bytes)
{
    struct ocnext_bridge_view v;
    int r;
    if (!data)
        return OCNEXT_CLIENT_ARGUMENT;
    r = data_prepare(c, h, offset, bytes);
    if (r)
        return r;
    memcpy(c->request + 104, data, bytes);
    r = exchange(c, OCNEXT_OP_BUFFER_WRITE, 40 + bytes, 16, &v, 0);
    if (r)
        return r;
    return get64(v.payload + 8) == bytes ? 0 : invalidate(c, OCNEXT_CLIENT_PROTOCOL);
}
int ocnext_client_buffer_copy(struct ocnext_client *c, struct ocnext_client_handle source,
                              uint64_t source_offset, struct ocnext_client_handle destination,
                              uint64_t destination_offset, size_t bytes)
{
    struct ocnext_bridge_view v;
    int r;
    if (!bytes || bytes > OCNEXT_BROKER_MAX_TRANSFER)
        return OCNEXT_CLIENT_ARGUMENT;
    r = prefix(c, 64);
    if (r)
        return r;
    handle_bytes(c->request + 72, source);
    handle_bytes(c->request + 88, destination);
    put64(c->request + 104, source_offset);
    put64(c->request + 112, destination_offset);
    put64(c->request + 120, bytes);
    r = exchange(c, OCNEXT_OP_BUFFER_COPY, 64, 16, &v, 0);
    if (r)
        return r;
    return get64(v.payload + 8) == bytes ? 0 : invalidate(c, OCNEXT_CLIENT_PROTOCOL);
}
int ocnext_client_session_reset(struct ocnext_client *c)
{
    struct ocnext_bridge_view v;
    int r = prefix(c, 8);
    if (r)
        return r;
    return exchange(c, OCNEXT_OP_DEVICE_RESET, 8, 8, &v, 0);
}
int ocnext_client_gpu_probe(struct ocnext_client *c)
{
    struct ocnext_bridge_view v;
    int r = prefix(c, 8);
    if (r)
        return r;
    return exchange(c, OCNEXT_OP_GPU_SUBMIT, 8, 8, &v, 0);
}
const char *ocnext_client_result_string(int r)
{
    switch (r)
    {
    case 0:
        return "ok";
    case -2001:
        return "invalid argument";
    case -2002:
        return "platform unavailable";
    case -2003:
        return "socket/peer identity rejected";
    case -2004:
        return "operation deadline exceeded";
    case -2005:
        return "connection I/O failed";
    case -2006:
        return "response protocol rejected";
    case -2007:
        return "client allocation failed";
    case -2008:
        return "client connection closed";
    case -2009:
        return "required capability unavailable";
    default:
        return "broker semantic status";
    }
}
