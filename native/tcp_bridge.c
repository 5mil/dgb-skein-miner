/* Rake :: tcp_bridge.c
 * POSIX blocking TCP socket implementation.
 * Windows support: define RAKE_WINDOWS; uses Winsock2.
 */

#include "tcp_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef RAKE_WINDOWS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  typedef SOCKET sock_t;
  #define INVALID_SOCK INVALID_SOCKET
  #define SOCK_ERR     SOCKET_ERROR
  static int winsock_init_done = 0;
  static void ensure_winsock(void) {
    if (!winsock_init_done) {
      WSADATA wd;
      WSAStartup(MAKEWORD(2,2), &wd);
      winsock_init_done = 1;
    }
  }
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/select.h>
  typedef int sock_t;
  #define INVALID_SOCK (-1)
  #define SOCK_ERR     (-1)
  static void ensure_winsock(void) {}
#endif

void rake_tcp_version_assert(void) {
  /* Checked at Unison startup; version must match header constant */
  (void)RAKE_TCP_BRIDGE_VERSION;
}

/* Split "host:port" into separate strings */
static int split_endpoint(const char *ep, char *host, size_t hlen,
                           char *port, size_t plen) {
  const char *colon = strrchr(ep, ':');
  if (!colon) return -1;
  size_t hostlen = (size_t)(colon - ep);
  if (hostlen >= hlen || strlen(colon+1) >= plen) return -1;
  memcpy(host, ep, hostlen);
  host[hostlen] = '\0';
  strncpy(port, colon+1, plen-1);
  port[plen-1] = '\0';
  return 0;
}

int rake_tcp_connect(const char *endpoint, int timeout_ms) {
  ensure_winsock();
  char host[256], port[16];
  if (split_endpoint(endpoint, host, sizeof(host), port, sizeof(port)) < 0) {
    fprintf(stderr, "[tcp] bad endpoint: %s\n", endpoint);
    return -1;
  }
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
    fprintf(stderr, "[tcp] getaddrinfo failed for %s\n", endpoint);
    return -1;
  }
  sock_t fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd == INVALID_SOCK) { freeaddrinfo(res); return -1; }

#ifndef RAKE_WINDOWS
  /* Set non-blocking for connect timeout */
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

  int rc = connect(fd, res->ai_addr, (int)res->ai_addrlen);
  freeaddrinfo(res);

#ifndef RAKE_WINDOWS
  if (rc < 0 && errno == EINPROGRESS) {
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    rc = select(fd+1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) {
      close(fd);
      fprintf(stderr, "[tcp] connect timeout to %s\n", endpoint);
      return -1;
    }
    int err = 0; socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) { close(fd); return -1; }
  } else if (rc < 0) { close(fd); return -1; }
  /* Restore blocking */
  fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
  if (rc == SOCK_ERR) { closesocket(fd); return -1; }
#endif

  fprintf(stderr, "[tcp] connected to %s (fd=%d)\n", endpoint, (int)fd);
  return (int)fd;
}

int rake_tcp_send(int fd, const uint8_t *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
#ifdef RAKE_WINDOWS
    int n = send((sock_t)fd, (const char*)(buf + sent), (int)(len - sent), 0);
#else
    ssize_t n = write(fd, buf + sent, len - sent);
#endif
    if (n <= 0) {
      perror("[tcp] send");
      return -1;
    }
    sent += (size_t)n;
  }
  return 0;
}

int rake_tcp_recv(int fd, uint8_t *buf, size_t buflen) {
#ifdef RAKE_WINDOWS
  int n = recv((sock_t)fd, (char*)buf, (int)buflen, 0);
#else
  ssize_t n = read(fd, buf, buflen);
#endif
  if (n < 0) { perror("[tcp] recv"); return -1; }
  return (int)n;
}

void rake_tcp_close(int fd) {
#ifdef RAKE_WINDOWS
  closesocket((sock_t)fd);
#else
  close(fd);
#endif
}

int rake_tcp_listen(uint16_t port, int backlog) {
  ensure_winsock();
  sock_t fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd == INVALID_SOCK) {
    /* fallback to IPv4 */
    fd = socket(AF_INET, SOCK_STREAM, 0);
  }
  if (fd == INVALID_SOCK) return -1;

  int yes = 1;
#ifndef RAKE_WINDOWS
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#else
  setsockopt((sock_t)fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
#endif

  struct sockaddr_in6 addr6;
  memset(&addr6, 0, sizeof(addr6));
  addr6.sin6_family = AF_INET6;
  addr6.sin6_port   = htons(port);
  addr6.sin6_addr   = in6addr_any;

  if (bind(fd, (struct sockaddr*)&addr6, sizeof(addr6)) < 0) {
    /* Try IPv4 fallback */
#ifdef RAKE_WINDOWS
    closesocket(fd);
#else
    close(fd);
#endif
    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family      = AF_INET;
    addr4.sin_port        = htons(port);
    addr4.sin_addr.s_addr = INADDR_ANY;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(yes));
    if (bind(fd, (struct sockaddr*)&addr4, sizeof(addr4)) < 0) {
      perror("[tcp] bind"); rake_tcp_close((int)fd); return -1;
    }
  }
  if (listen(fd, backlog) < 0) {
    perror("[tcp] listen"); rake_tcp_close((int)fd); return -1;
  }
  fprintf(stderr, "[tcp] listening on port %d (fd=%d)\n", port, (int)fd);
  return (int)fd;
}

int rake_tcp_accept(int listen_fd) {
  sock_t client = accept((sock_t)listen_fd, NULL, NULL);
  if (client == INVALID_SOCK) { perror("[tcp] accept"); return -1; }
  return (int)client;
}
