#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ocnext/broker.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop_handler(int number) { (void)number; stopping = 1; }

static void *allocate_memory(void *context, size_t bytes, size_t alignment)
{
    (void)context;
    (void)alignment; /* engine accepts only malloc-compatible alignments */
    return malloc(bytes);
}

static void free_memory(void *context, void *memory, size_t bytes, size_t alignment)
{
    (void)context; (void)bytes; (void)alignment;
    free(memory);
}

static int read_exact(int fd, void *memory, size_t bytes)
{
    uint8_t *p = memory;
    size_t done = 0;
    while (done < bytes && !stopping) {
        ssize_t n = read(fd, p + done, bytes - done);
        if (n > 0) done += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else return 0;
    }
    return done == bytes;
}

static int write_exact(int fd, const void *memory, size_t bytes)
{
    const uint8_t *p = memory;
    size_t done = 0;
    while (done < bytes && !stopping) {
        ssize_t n = write(fd, p + done, bytes - done);
        if (n > 0) done += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else return 0;
    }
    return done == bytes;
}

static int same_user(int fd)
{
#if defined(__APPLE__) || defined(__FreeBSD__)
    uid_t uid;
    gid_t gid;
    return getpeereid(fd, &uid, &gid) == 0 && uid == geteuid();
#elif defined(__linux__)
    struct ucred credentials;
    socklen_t size = sizeof(credentials);
    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0 &&
           size == sizeof(credentials) && credentials.uid == geteuid();
#else
    (void)fd;
    return 0; /* fail closed on platforms without an implemented credential API */
#endif
}

static uint32_t total_size(const uint8_t *p)
{
    return (uint32_t)p[12] | ((uint32_t)p[13] << 8) |
           ((uint32_t)p[14] << 16) | ((uint32_t)p[15] << 24);
}

static void unlink_owned_socket(const char *path, const struct stat *created)
{
    struct stat current;
    if (S_ISSOCK(created->st_mode) && created->st_uid == geteuid() &&
        lstat(path, &current) == 0 && S_ISSOCK(current.st_mode) &&
        current.st_dev == created->st_dev && current.st_ino == created->st_ino)
        unlink(path);
}

static void serve_client(int fd, struct ocnext_broker *broker, uint64_t owner)
{
    struct timeval timeout = {5, 0};
    uint8_t response[OCNEXT_BROKER_DATA_RESPONSE_CAPACITY];
    uint8_t *request;
    unsigned int requests = 0;
    if (!same_user(fd)) return;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) return;
    request = malloc(OCNEXT_BRIDGE_MAX_MESSAGE);
    if (request == NULL) return;
    while (!stopping && requests++ < 65536) {
        uint32_t bytes;
        size_t response_size;
        if (!read_exact(fd, request, OCNEXT_BRIDGE_HEADER_SIZE)) break;
        bytes = total_size(request);
        if (bytes < OCNEXT_BRIDGE_HEADER_SIZE || bytes > OCNEXT_BRIDGE_MAX_MESSAGE) break;
        if (!read_exact(fd, request + OCNEXT_BRIDGE_HEADER_SIZE,
                        bytes - OCNEXT_BRIDGE_HEADER_SIZE)) break;
        if (ocnext_broker_dispatch(broker, owner, request, bytes,
                response, sizeof(response), &response_size) != OCNEXT_BROKER_DISPATCH_OK) break;
        if (!write_exact(fd, response, response_size)) break;
    }
    free(request);
    ocnext_broker_disconnect(broker, owner);
}

int main(int argc, char **argv)
{
    const char *path = ".cache/broker.sock";
    struct sockaddr_un address;
    struct stat before, bound;
    struct sigaction action;
    struct ocnext_broker_limits limits = ocnext_broker_default_limits();
    struct ocnext_broker_allocator allocator = {NULL, allocate_memory, free_memory};
    struct ocnext_broker *broker;
    void *storage;
    uint64_t owner = 1;
    int listener, exit_status = 0;
    mode_t previous_umask;
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: ocnext-broker [--socket PATH]\nLocal same-UID CPU-buffer research broker; no GPU or EFI runtime.");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--socket") == 0) path = argv[2];
    else if (argc != 1) { fputs("Invalid arguments; use --help.\n", stderr); return 2; }
    if (geteuid() == 0) { fputs("Run as a regular user, not root.\n", stderr); return 2; }
    if (strlen(path) == 0 || strlen(path) >= sizeof(address.sun_path)) {
        fputs("Socket path too long or empty.\n", stderr); return 2;
    }
    if (strcmp(path, ".cache/broker.sock") == 0 && mkdir(".cache", 0700) != 0 && errno != EEXIST) {
        perror("mkdir .cache"); return 1;
    }
    if (lstat(path, &before) == 0 || errno != ENOENT) {
        fputs("Socket path already exists or cannot be inspected; refusing to replace it.\n", stderr);
        return 1;
    }
    storage = malloc(ocnext_broker_storage_size());
    if (storage == NULL) return 1;
    broker = ocnext_broker_init(storage, ocnext_broker_storage_size(), &limits, &allocator);
    if (broker == NULL) { free(storage); return 1; }
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); free(storage); return 1; }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    previous_umask = umask(077);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("bind"); umask(previous_umask); close(listener); free(storage); return 1;
    }
    umask(previous_umask);
    if (lstat(path, &bound) != 0) {
        perror("socket identity"); close(listener); free(storage); return 1;
    }
    if (!S_ISSOCK(bound.st_mode) || bound.st_uid != geteuid() ||
        chmod(path, 0600) != 0 || listen(listener, 4) != 0) {
        perror("socket setup"); close(listener); unlink_owned_socket(path, &bound); free(storage); return 1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction"); exit_status = 1; stopping = 1;
    }
    signal(SIGPIPE, SIG_IGN);
    printf("ocnext-broker ready: %s (same UID, CPU buffers only, GPU unsupported)\n", path);
    fflush(stdout);
    while (!stopping) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept"); exit_status = 1; break;
        }
        if (owner == UINT64_MAX) { close(client); exit_status = 1; break; }
        serve_client(client, broker, owner++);
        close(client);
    }
    close(listener);
    ocnext_broker_destroy(broker);
    free(storage);
    unlink_owned_socket(path, &bound);
    return exit_status;
}
