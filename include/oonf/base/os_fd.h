
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

#ifndef OS_FD_H_
#define OS_FD_H_

#if 0
/* pre-definition of structs */
struct os_fd;
struct os_fd_select;
#endif

#include <sys/select.h>
#include <unistd.h>

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>

#include <oonf/base/os_fd_data.h>

#if 0
/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_fd_linux_data.h>
#elif defined(BSD)
#error "Unknown operation system"
#endif
#endif

/*! subsystem identifier */
#define OONF_OS_FD_SUBSYSTEM "os_fd"

/* pre-declare inlines */
static INLINE int os_fd_init(struct os_fd *, int fd);
static INLINE int os_fd_copy(struct os_fd *dst, struct os_fd *from);
static INLINE int os_fd_get_fd(struct os_fd *);
static INLINE int os_fd_invalidate(struct os_fd *);
static INLINE bool os_fd_is_initialized(struct os_fd *);

static INLINE int os_fd_bindto_interface(struct os_fd *, struct os_interface *);
static INLINE int os_fd_close(struct os_fd *);
static INLINE int os_fd_listen(struct os_fd *, int n);

static INLINE int os_fd_event_add(struct os_fd_select *);
static INLINE int os_fd_event_socket_add(struct os_fd_select *, struct os_fd *);
static INLINE int os_fd_event_socket_read(struct os_fd_select *, struct os_fd *, bool want_read);
static INLINE int os_fd_event_is_read(struct os_fd *);
static INLINE int os_fd_event_socket_write(struct os_fd_select *, struct os_fd *, bool want_write);
static INLINE int os_fd_event_is_write(struct os_fd *);
static INLINE int os_fd_event_socket_remove(struct os_fd_select *, struct os_fd *);
static INLINE int os_fd_event_set_deadline(struct os_fd_select *, uint64_t deadline);
static INLINE uint64_t os_fd_event_get_deadline(struct os_fd_select *);
static INLINE int os_fd_event_wait(struct os_fd_select *);
static INLINE struct os_fd *os_fd_event_get(struct os_fd_select *, int idx);
static INLINE int os_fd_event_remove(struct os_fd_select *);

static INLINE int os_fd_connect(struct os_fd *, const union netaddr_socket *remote);
static INLINE int os_fd_accept(struct os_fd *client, struct os_fd *server, union netaddr_socket *incoming);
static INLINE int os_fd_get_socket_error(struct os_fd *, int *value);
static INLINE ssize_t os_fd_sendto(
  struct os_fd *, const void *buf, size_t length, const union netaddr_socket *dst, bool dont_route);
static INLINE ssize_t os_fd_recvfrom(
  struct os_fd *, void *buf, size_t length, union netaddr_socket *source, const struct os_interface *);
static INLINE const char *os_fd_get_loopback_name(void);
static INLINE ssize_t os_fd_sendfile(struct os_fd *, struct os_fd *, size_t offset, size_t count);

static INLINE int os_fd_getsocket(struct os_fd *, const union netaddr_socket *bindto, bool tcp, size_t recvbuf,
  const struct os_interface *, enum oonf_log_source log_src);
static INLINE int os_fd_getrawsocket(struct os_fd *, const union netaddr_socket *bindto, int protocol, size_t recvbuf,
  const struct os_interface *, enum oonf_log_source log_src);
static INLINE int os_fd_configsocket(struct os_fd *, const union netaddr_socket *bindto, size_t recvbuf, bool rawip,
  const struct os_interface *, enum oonf_log_source log_src);
static INLINE int os_fd_set_nonblocking(struct os_fd *);
static INLINE int os_fd_join_mcast_recv(
  struct os_fd *, const struct netaddr *multicast, const struct os_interface *, enum oonf_log_source log_src);
static INLINE int os_fd_join_mcast_send(struct os_fd *, const struct netaddr *multicast, const struct os_interface *,
  bool loop, uint8_t ttl, enum oonf_log_source log_src);
static INLINE int os_fd_set_dscp(struct os_fd *, int dscp, bool ipv6);
static INLINE uint8_t *os_fd_skip_rawsocket_prefix(uint8_t *ptr, ssize_t *len, int af_type);

/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_fd_linux.h>
#elif defined(BSD)
#error "Unknown operation system"
#endif

#endif /* OS_FD_H_ */
