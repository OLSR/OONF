
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
 * Copyright (c) 2004-2015, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

/**
 * @file
 */

#ifndef OS_FD_LINUX_H_
#define OS_FD_LINUX_H_

#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <oonf/base/os_interface.h>
#include <oonf/base/os_fd_data.h>
#include <oonf/base/os_generic/os_fd_generic_configsocket.h>
#include <oonf/base/os_generic/os_fd_generic_getrawsocket.h>
#include <oonf/base/os_generic/os_fd_generic_getsocket.h>
#include <oonf/base/os_generic/os_fd_generic_join_mcast.h>
#include <oonf/base/os_generic/os_fd_generic_set_dscp.h>
#include <oonf/base/os_generic/os_fd_generic_set_nonblocking.h>

/** declare non-inline linux-specific functions */
EXPORT int os_fd_linux_event_wait(struct os_fd_select *);
EXPORT int os_fd_linux_event_socket_modify(struct os_fd_select *sel, struct os_fd *sock);
EXPORT uint8_t *os_fd_linux_skip_rawsocket_prefix(uint8_t *ptr, ssize_t *len, int af_type);

/**
 * Redirect to linux specific event wait call
 * @param sel selector instance
 * @return number of events that happened,
 *   0 if deadline was reached, -1 if an error happened
 */
static INLINE int
os_fd_event_wait(struct os_fd_select *sel) {
  return os_fd_linux_event_wait(sel);
}

/**
 * Redirect to generic getsocket call
 * @param sock empty socket representation
 * @param bindto bind socket to this address/port
 * @param tcp true if TCP socket, false if UDP socket
 * @param recvbuf size of receiver buffer
 * @param os_if bind socket to this interface,
 *   NULL to not bind socket to interface
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_getsocket(struct os_fd *sock, const union netaddr_socket *bindto, bool tcp, size_t recvbuf,
  const struct os_interface *os_if, enum oonf_log_source log_src) {
  return os_fd_generic_getsocket(sock, bindto, tcp, recvbuf, os_if, log_src);
}

/**
 * Redirect to generic getrawsocket call
 * @param sock empty socket representation
 * @param bindto bind socket to this address/port
 * @param protocol bind socket to this protocol
 * @param recvbuf size of receiver buffer
 * @param os_if bind socket to this interface,
 *   NULL to not bind socket to interface
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_getrawsocket(struct os_fd *sock, const union netaddr_socket *bindto, int protocol, size_t recvbuf,
  const struct os_interface *os_if, enum oonf_log_source log_src) {
  return os_fd_generic_getrawsocket(sock, bindto, protocol, recvbuf, os_if, log_src);
}

/**
 * Redirect to generic configsocket call
 * @param sock empty socket representation
 * @param bindto bind socket to this address/port
 * @param recvbuf size of receiver buffer
 * @param rawip true if this is a raw ip socket, false otherwise
 * @param os_if bind socket to this interface,
 *   NULL to not bind socket to interface
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_configsocket(struct os_fd *sock, const union netaddr_socket *bindto, size_t recvbuf, bool rawip,
  const struct os_interface *os_if, enum oonf_log_source log_src) {
  return os_fd_generic_configsocket(sock, bindto, recvbuf, rawip, os_if, log_src);
}

/**
 * Redirect to generic set_nonblocking call
 * @param sock socket representation
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_set_nonblocking(struct os_fd *sock) {
  return os_fd_generic_set_nonblocking(sock);
}

/**
 * Redirect to generic mcast receiver join call
 * @param sock socket representation
 * @param multicast multicast group to join
 * @param os_if outgoing interface for multicast,
 *   NULL if not interface specific
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_join_mcast_recv(
  struct os_fd *sock, const struct netaddr *multicast, const struct os_interface *os_if, enum oonf_log_source log_src) {
  return os_fd_generic_join_mcast_recv(sock, multicast, os_if, log_src);
}

/**
 * Redirect to generic mcast sender join call
 * @param sock socket representation
 * @param multicast sending multicast group to join
 * @param os_if outgoing interface for multicast,
 *   NULL if not interface specific
 * @param loop true if multicast should be locally looped
 * @param ttl TTL of the multicast, 0 will be considered as ttl 1
 * @param log_src logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_join_mcast_send(struct os_fd *sock, const struct netaddr *multicast, const struct os_interface *os_if, bool loop,
  uint8_t ttl, enum oonf_log_source log_src) {
  return os_fd_generic_join_mcast_send(sock, multicast, os_if, loop, ttl, log_src);
}
/**
 * Redirect to generic set_dscp call
 * @param sock socket representation
 * @param dscp new dscp value
 * @param ipv6 true if IPv6, false for IPv4 socket
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_set_dscp(struct os_fd *sock, int dscp, bool ipv6) {
  return os_fd_generic_set_dscp(sock, dscp, ipv6);
}

/**
 * Redirect to linux specific rawsocket prefix call
 * @param ptr pointer to the beginning of the buffer
 * @param len pointer to length of buffer
 * @param af_type address family of data in buffer
 * @return pointer to transport layer data
 */
static INLINE uint8_t *
os_fd_skip_rawsocket_prefix(uint8_t *ptr, ssize_t *len, int af_type) {
  return os_fd_linux_skip_rawsocket_prefix(ptr, len, af_type);
}

/**
 * initialize a socket representation with a file descriptor
 * @param os_fd socket representation
 * @param fd file descriptor
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_init(struct os_fd *os_fd, int fd) {
  os_fd->fd = fd;
  os_fd->_flags = OS_FD_ACTIVE;
  return 0;
}

/**
 * Removes all data from a socket. it is not necessary to
 * call this function on all sockets.
 * @param sock socket representation
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_invalidate(struct os_fd *sock) {
  memset(sock, 0, sizeof(*sock));
  return 0;
}

/**
 * Checks if a socket is initialized
 * @param sock socket representation
 * @return true if socket is initialized, false otherwise
 */
static INLINE bool
os_fd_is_initialized(struct os_fd *sock) {
  return (sock->_flags & OS_FD_ACTIVE) != 0;
}

/**
 * Extract the filedescriptor from a socket
 * @param sock socket representation
 * @return file descriptor
 */
static INLINE int
os_fd_get_fd(struct os_fd *sock) {
  return sock->fd;
}

/**
 * Copy a filedescriptor
 * @param dst target filedescriptor
 * @param from source filedescriptor
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_copy(struct os_fd *dst, struct os_fd *from) {
  return os_fd_init(dst, from->fd);
}

/**
 * Close a file descriptor
 * @param fd filedescriptor
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_close(struct os_fd *fd) {
  int result = 0;
  if (fd->fd != -1) {
    result = close(fd->fd);
    fd->fd = -1;
  }
  return result;
}

/**
 * Listen to a TCP socket
 * @param fd filedescriptor
 * @param n backlog
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_listen(struct os_fd *fd, int n) {
  return listen(fd->fd, n);
}

/**
 * Initialize a socket event handler
 * @param sel empty socket event handler
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_event_add(struct os_fd_select *sel) {
  memset(sel, 0, sizeof(*sel));
  sel->_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  return sel->_epoll_fd < 0 ? -1 : 0;
}

/**
 * Get an event from a socket event handler
 * @param sel socket event handler
 * @param idx index of event
 * @return socket responsible for event
 */
static INLINE struct os_fd *
os_fd_event_get(struct os_fd_select *sel, int idx) {
  return sel->_events[idx].data.ptr;
}

/**
 * Add a socket to a socket event handler
 * @param sel socket event handler
 * @param sock socket
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_event_socket_add(struct os_fd_select *sel, struct os_fd *sock) {
  struct epoll_event event;

  memset(&event, 0, sizeof(event));

  event.events = 0;
  event.data.ptr = sock;
  return epoll_ctl(sel->_epoll_fd, EPOLL_CTL_ADD, sock->fd, &event);
}

/**
 * Set the read status of a socket in a socket event handler
 * @param sel socket event handler
 * @param sock socket representation
 * @param want_read true if socket should trigger read events,
 *   false otherwise
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_event_socket_read(struct os_fd_select *sel, struct os_fd *sock, bool want_read) {
  if (want_read) {
    sock->wanted_events |= EPOLLIN;
  }
  else {
    sock->wanted_events &= ~EPOLLIN;
  }
  return os_fd_linux_event_socket_modify(sel, sock);
}

/**
 * Check if a socket triggered a read event
 * @param sock socket representation
 * @return true if socket triggered a read event, false otherwise
 */
static INLINE int
os_fd_event_is_read(struct os_fd *sock) {
  return (sock->received_events & EPOLLIN) != 0;
}

/**
 * Set the write status of a socket in a socket event handler
 * @param sel socket event handler
 * @param sock socket representation
 * @param want_write true if socket should trigger write events,
 *   false otherwise
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_event_socket_write(struct os_fd_select *sel, struct os_fd *sock, bool want_write) {
  if (want_write) {
    sock->wanted_events |= EPOLLOUT;
  }
  else {
    sock->wanted_events &= ~EPOLLOUT;
  }
  return os_fd_linux_event_socket_modify(sel, sock);
}

/**
 * Check if a socket triggered a write event
 * @param sock socket representation
 * @return true if socket triggered a write event, false otherwise
 */
static INLINE int
os_fd_event_is_write(struct os_fd *sock) {
  return (sock->received_events & EPOLLOUT) != 0;
}

/**
 * Remove a socket fromo a socket event handler
 * @param sel socket event handler
 * @param sock socket representation
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_event_socket_remove(struct os_fd_select *sel, struct os_fd *sock) {
  return epoll_ctl(sel->_epoll_fd, EPOLL_CTL_DEL, sock->fd, NULL);
}

/**
 * Set the deadline for the coming socket event wait operations
 * @param sel socket event handler
 * @param deadline absolute timestamp when the wait call should return
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_event_set_deadline(struct os_fd_select *sel, uint64_t deadline) {
  sel->deadline = deadline;
  return 0;
}

/**
 * @param sel socket event handler
 * @return current deadline for wait call
 */
static INLINE uint64_t
os_fd_event_get_deadline(struct os_fd_select *sel) {
  return sel->deadline;
}

/**
 * Cleans up a socket event handler
 * @param sel socket event handler
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_event_remove(struct os_fd_select *sel) {
  return close(sel->_epoll_fd);
}

/**
 * Connect TCP socket to remote server
 * @param sockfd filedescriptor
 * @param remote remote socket
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_connect(struct os_fd *sockfd, const union netaddr_socket *remote) {
  return connect(sockfd->fd, &remote->std, sizeof(*remote));
}

/**
 * Call posix accept()
 * @param client storage for filedescriptor for incoming session
 * @param server server socket to accept a connection from
 * @param incoming buffer for storing the incoming source IP/port
 * @return result of accept() call
 */
static INLINE int
os_fd_accept(struct os_fd *client, struct os_fd *server, union netaddr_socket *incoming) {
  socklen_t len = sizeof(*incoming);
  int fd;

  if ((fd = accept(server->fd, &incoming->std, &len)) < 0) {
    return -1;
  }
  return os_fd_init(client, fd);
}

/**
 * Get socket error state
 * @param sockfd file descriptor of socket
 * @param value buffer to store error state
 * @return result of getsockopt() call
 */
static INLINE int
os_fd_get_socket_error(struct os_fd *sockfd, int *value) {
  socklen_t len = sizeof(*value);
  return getsockopt(sockfd->fd, SOL_SOCKET, SO_ERROR, value, &len);
}

/**
 * Sends data to an UDP socket.
 * @param sock filedescriptor of UDP socket
 * @param buf buffer for target data
 * @param length length of buffer
 * @param dst pointer to netaddr socket to send packet to
 * @param dont_route true to suppress routing of data
 * @return same as sendto()
 */
static INLINE ssize_t
os_fd_sendto(struct os_fd *sock, const void *buf, size_t length, const union netaddr_socket *dst, bool dont_route) {
  if (dst) {
    return sendto(sock->fd, buf, length, dont_route ? MSG_DONTROUTE : 0, &dst->std, sizeof(*dst));
  }
  else {
    return send(sock->fd, buf, length, dont_route ? MSG_DONTROUTE : 0);
  }
}

/**
 * Receive data from an UDP socket.
 * @param sockfd filedescriptor of UDP socket
 * @param buf buffer for incoming data
 * @param length length of buffer
 * @param source pointer to netaddr socket object to store source of packet
 * @param interf limit received data to certain interface
 *   (only used if socket cannot be bound to interface)
 * @return same as recvfrom()
 */
static INLINE ssize_t
os_fd_recvfrom(struct os_fd *sockfd, void *buf, size_t length, union netaddr_socket *source,
  const struct os_interface *interf __attribute__((unused))) {
  socklen_t len = sizeof(*source);
  if (source) {
    return recvfrom(sockfd->fd, buf, length, 0, &source->std, &len);
  }
  else {
    return recv(sockfd->fd, buf, length, 0);
  }
}

/**
 * Binds a socket to a certain interface
 * @param sock filedescriptor of socket
 * @param interf interface to bind the socket to
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_fd_bindto_interface(struct os_fd *sock, struct os_interface *interf) {
  return setsockopt(sock->fd, SOL_SOCKET, SO_BINDTODEVICE, interf->name, strlen(interf->name) + 1);
}

/**
 * @return name of loopback interface
 */
static INLINE const char *
os_fd_get_loopback_name(void) {
  return "lo";
}

/**
 * send data from one filedescriptor to another one. Linux compatible API
 * structure, might need a bit of work for other OS.
 * @param out destination file descriptor
 * @param in source file descriptor
 * @param offset offset where to start reading from source
 * @param count number of bytes to copy
 * @return -1 if an error happened, otherwise the number of bytes that
 *   were sent to outfd
 */
static INLINE ssize_t
os_fd_sendfile(struct os_fd *out, struct os_fd *in, size_t offset, size_t count) {
  off_t int_offset = offset;
  return sendfile(out->fd, in->fd, &int_offset, count);
}

#endif /* OS_FD_LINUX_H_ */
