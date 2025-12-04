
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

#ifndef OONF_SOCKET_H_
#define OONF_SOCKET_H_

struct oonf_socket_entry;

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/base/os_fd.h>
#include <oonf/base/oonf_socket_data.h>

/*! subsystem identifier */
#define OONF_SOCKET_SUBSYSTEM "socket"

EXPORT void oonf_socket_add(struct oonf_socket_entry *);
EXPORT void oonf_socket_remove(struct oonf_socket_entry *);
EXPORT void oonf_socket_set_read(struct oonf_socket_entry *entry, bool event_read);
EXPORT void oonf_socket_set_write(struct oonf_socket_entry *entry, bool event_write);
EXPORT struct list_entity *oonf_socket_get_list(void);

/**
 * @param entry socket entry
 * @return true if socket has a read event, false otherwise
 */
static INLINE bool
oonf_socket_is_read(struct oonf_socket_entry *entry) {
  return os_fd_event_is_read(&entry->fd);
}

/**
 * @param entry socket entry
 * @return true if socket has a write event, false otherwise
 */
static INLINE bool
oonf_socket_is_write(struct oonf_socket_entry *entry) {
  return os_fd_event_is_write(&entry->fd);
}

/**
 * Registers a direct send (without select) to a socket
 * @param entry socket entry
 */
static INLINE void
oonf_socket_register_direct_send(struct oonf_socket_entry *entry) {
  entry->_stat_send++;
}

/**
 * @param sock pointer to socket entry
 * @return number of recv events of socket
 */
static INLINE uint32_t
oonf_socket_get_recv(struct oonf_socket_entry *sock) {
  return sock->_stat_recv;
}

/**
 * @param sock pointer to socket entry
 * @return number of send events of socket
 */
static INLINE uint32_t
oonf_socket_get_send(struct oonf_socket_entry *sock) {
  return sock->_stat_send;
}

/**
 * @param sock pointer to socket entry
 * @return number of times socket handling took more than a timer slice
 */
static INLINE uint32_t
oonf_socket_get_long(struct oonf_socket_entry *sock) {
  return sock->_stat_long;
}

#endif /* OONF_SOCKET_H_ */
