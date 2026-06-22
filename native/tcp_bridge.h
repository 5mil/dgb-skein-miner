/* Rake :: tcp_bridge.h
 * Minimal blocking TCP socket bridge for Unison FFI.
 *
 * Each Socket is an opaque int (file descriptor on POSIX,
 * SOCKET handle on Windows wrapped to int).
 * All functions return -1 / NULL on error and set errno.
 *
 * Thread safety: each fd is owned by exactly one Unison thread.
 * The recv buffer is caller-allocated; callers must size it adequately.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version assertion — must match rake_tcp_version_assert() constant */
#define RAKE_TCP_BRIDGE_VERSION 1

void rake_tcp_version_assert(void);

/*
 * Connect to host:port (blocking, with timeout_ms).
 * endpoint format: "host:port" e.g. "stratum.mining-dutch.nl:5020"
 * Returns fd >= 0 on success, -1 on error.
 */
int rake_tcp_connect(const char *endpoint, int timeout_ms);

/*
 * Send exactly len bytes from buf.
 * Returns 0 on success, -1 on error.
 */
int rake_tcp_send(int fd, const uint8_t *buf, size_t len);

/*
 * Blocking recv up to buflen bytes into buf.
 * Returns bytes received (>0), 0 on clean close, -1 on error.
 */
int rake_tcp_recv(int fd, uint8_t *buf, size_t buflen);

/*
 * Close the socket.
 */
void rake_tcp_close(int fd);

/*
 * Listen on 0.0.0.0:port (for API server).
 * Returns listening fd >= 0, or -1 on error.
 */
int rake_tcp_listen(uint16_t port, int backlog);

/*
 * Accept one connection from listening fd.
 * Returns client fd >= 0, or -1 on error.
 */
int rake_tcp_accept(int listen_fd);

#ifdef __cplusplus
}
#endif
