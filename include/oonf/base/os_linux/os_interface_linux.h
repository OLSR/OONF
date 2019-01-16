
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

#ifndef OS_INTERFACE_LINUX_H_
#define OS_INTERFACE_LINUX_H_

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <oonf/oonf.h>
#include <oonf/base/os_generic/os_interface_generic.h>
#include <oonf/base/os_interface.h>
#include <oonf/base/os_linux/os_interface_linux_data.h>

EXPORT struct os_interface *os_interface_linux_add(struct os_interface_listener *);
EXPORT void os_interface_linux_remove(struct os_interface_listener *);
EXPORT struct avl_tree *os_interface_linux_get_tree(void);

EXPORT void os_interface_linux_trigger_handler(struct os_interface_listener *);

EXPORT int os_interface_linux_state_set(struct os_interface *, bool up);
EXPORT int os_interface_linux_mac_set(struct os_interface *interf, struct netaddr *mac);

EXPORT int os_interface_linux_address_set(struct os_interface_ip_change *addr);
EXPORT void os_interface_linux_address_interrupt(struct os_interface_ip_change *addr);

/**
 * Add an interface to the OONF handling
 * @param interf network interface
 * @return interface data object
 */
static INLINE struct os_interface *
os_interface_add(struct os_interface_listener *interf) {
  return os_interface_linux_add(interf);
}

/**
 * Remove an interface from the OONF handling
 * @param interf network interface
 */
static INLINE void
os_interface_remove(struct os_interface_listener *interf) {
  os_interface_linux_remove(interf);
}

/**
 * @return tree of network interfaces
 */
static INLINE struct avl_tree *
os_interface_get_tree(void) {
  return os_interface_linux_get_tree();
}

/**
 * Trigger an interface change handler
 * @param interf network interface
 */
static INLINE void
os_interface_trigger_handler(struct os_interface_listener *interf) {
  os_interface_linux_trigger_handler(interf);
}

/**
 * Set interface up or down
 * @param os_if network interface
 * @param up true if interface should be up, false if down
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_interface_state_set(struct os_interface *os_if, bool up) {
  return os_interface_linux_state_set(os_if, up);
}

/**
 * Set or remove an IP address from an interface
 * @param addr interface address change request
 * @return -1 if the request could not be sent to the server,
 *   0 otherwise
 */
static INLINE int
os_interface_address_set(struct os_interface_ip_change *addr) {
  return os_interface_linux_address_set(addr);
}

/**
 * Stop processing an interface address change
 * @param addr interface address change request
 */
static INLINE void
os_interface_address_interrupt(struct os_interface_ip_change *addr) {
  os_interface_linux_address_interrupt(addr);
}

/**
 * Set mac address of interface
 * @param os_if interface data object
 * @param mac new mac address
 * @return -1 if an error happened, 0 otherwise
 */
static INLINE int
os_interface_mac_set(struct os_interface *os_if, struct netaddr *mac) {
  return os_interface_linux_mac_set(os_if, mac);
}

static INLINE struct os_interface *
os_interface_get_data_by_ifindex(unsigned ifindex) {
  return os_interface_generic_get_data_by_ifindex(ifindex);
}

static INLINE struct os_interface *
os_interface_get_data_by_ifbaseindex(unsigned ifindex) {
  return os_interface_generic_get_data_by_ifbaseindex(ifindex);
}

static INLINE const struct netaddr *
os_interface_get_bindaddress(int af_type, struct netaddr_acl *filter, struct os_interface *ifdata) {
  return os_interface_generic_get_bindaddress(af_type, filter, ifdata);
}

static INLINE const struct os_interface_ip *
os_interface_get_prefix_from_dst(struct netaddr *destination, struct os_interface *ifdata) {
  return os_interface_generic_get_prefix_from_dst(destination, ifdata);
}

#endif /* OS_INTERFACE_LINUX_H_ */
