
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

#ifndef OS_SYSTEM_LINUX_H_
#define OS_SYSTEM_LINUX_H_

struct os_system_netlink_message;
struct os_system_netlink_socket;
struct os_system_netlink;

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_linux/os_system_linux_data.h>

EXPORT bool os_system_linux_is_ipv6_supported(void);

EXPORT bool os_system_linux_is_minimal_kernel(int v1, int v2, int v3);
EXPORT int os_system_linux_netlink_add(struct os_system_netlink *, int protocol);
EXPORT void os_system_linux_netlink_remove(struct os_system_netlink *);
EXPORT void os_system_linux_netlink_send(struct os_system_netlink *fd, struct os_system_netlink_message *msg);

EXPORT int os_system_linux_netlink_addreq(
  struct os_system_netlink_message *nl_msg, int type, const void *data, int len);

EXPORT int os_system_linux_linux_get_ioctl_fd(int af_type);

/**
 * @return true if IPv6 is supported, false otherwise
 */
static INLINE bool
os_system_is_ipv6_supported(void) {
  return os_system_linux_is_ipv6_supported();
}

/**
 * Adds an address TLV to a netlink stream
 * @param nl_msg netlink message
 * @param type netlink TLV type
 * @param addr address
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_system_linux_netlink_addnetaddr(struct os_system_netlink_message *nl_msg, int type, const struct netaddr *addr) {
  return os_system_linux_netlink_addreq(nl_msg, type, netaddr_get_binptr(addr), netaddr_get_maxprefix(addr) / 8);
}

static INLINE bool
os_system_linux_netlink_is_done(struct os_system_netlink_message *nl_msg) {
  return !list_is_node_added(&nl_msg->_node);
}

static INLINE void
os_system_linux_netlink_interrupt(struct os_system_netlink_message *nl_msg) {
  if (list_is_node_added(&nl_msg->_node)) {
    list_remove(&nl_msg->_node);
  }
}

#endif /* OS_SYSTEM_LINUX_H_ */
