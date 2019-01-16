
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

#ifndef OS_INTERFACE_H_
#define OS_INTERFACE_H_

struct os_interface_ip_change;
struct os_interface_flags;
struct os_interface;
struct os_interface_ip;
struct os_interface_listener;

#include <stdio.h>
#include <sys/time.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>

/*! subsystem identifier */
#define OONF_OS_INTERFACE_SUBSYSTEM "os_interface"

/*! interface configuration section name */
#define CFG_OSIF_SCHEMA_INTERFACE_SECTION_INIT .type = "interface", .mode = CFG_SSMODE_NAMED

/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_interface_linux_data.h>
#else
#error "Unknown operation system"
#endif

/**
 * Handler for changing an interface address
 */
struct os_interface_ip_change {
  /*! operation system specific data */
  struct os_interface_address_change_internal _internal;

  /*! interface address */
  struct netaddr address;

  /*! index of interface */
  unsigned int if_index;

  /*! address scope */
  enum os_addr_scope scope;

  /*! set or reset address */
  bool set;

  /**
   * Callback triggered when interface address has been changed
   * @param addr this interface address object
   * @param error error code, 0 if everything is fine
   */
  void (*cb_finished)(struct os_interface_ip_change *addr, int error);
};

struct os_interface_flags {
  /*! true if the interface exists and is up */
  bool up;

  /*! true if the interface is in promiscious mode */
  bool promisc;

  /*! true if the interface is point to point */
  bool pointtopoint;

  /*! true if the interface is a loopback one */
  bool loopback;

  /*! true if interface is the wildcard interface */
  bool any;

  /*! true if interface supports no multicast */
  bool unicast_only;

  /*! true if interface is used for meshing */
  bool mesh;
};

/**
 * Representation of an operation system interface
 */
struct os_interface {
  /*! operation system specific data */
  struct os_interface_internal _internal;

  /*! interface name */
  char name[IF_NAMESIZE];

  /*! interface index */
  unsigned index;

  /**
   * interface index of base interface (for vlan),
   * same for normal interface
   */
  unsigned base_index;

  /*! boolean flags of interface */
  struct os_interface_flags flags;

  /*! mac address of interface */
  struct netaddr mac;

  /**
   * point to one (mesh scope) IPv4 address of the interface
   * (or to NETADDR_UNSPEC if none available)
   */
  const struct netaddr *if_v4;

  /**
   * point to one (mesh scope) IPv4 address of the interface
   * (or to NETADDR_UNSPEC if none available)
   */
  const struct netaddr *if_v6;

  /**
   * point to one (linklocal scope) IPv4 address of the interface
   * (or to NETADDR_UNSPEC if none available)
   */
  const struct netaddr *if_linklocal_v4;

  /**
   * point to one (linklocal scope) IPv6 address of the interface
   * (or to NETADDR_UNSPEC if none available)
   */
  const struct netaddr *if_linklocal_v6;

  /*! tree of all addresses/prefixes of this interface */
  struct avl_tree addresses;

  /*! tree of all peer addresses/prefixes of this interface */
  struct avl_tree peers;

  /*! listeners to be informed when an interface changes */
  struct list_entity _listeners;

  /**
   * When an interface change handler triggers a 'interface not ready'
   * error the interface should be triggered again. The variable stores
   * the last interval until the next trigger.
   */
  uint64_t retrigger_timeout;

  /*! hook interfaces into global tree */
  struct avl_node _node;

  /*! timer for lazy interface change handling */
  struct oonf_timer_instance _change_timer;

  /*! remember if we already initialized the link data */
  bool _link_initialized;

  /*! remember if we already initialized the address data */
  bool _addr_initialized;
};

/**
 * Representation of an IP address/prefix of a network interface of
 * the operation system
 */
struct os_interface_ip {
  struct avl_node _node;

  struct netaddr prefixed_addr;
  struct netaddr address;
  struct netaddr prefix;

  struct os_interface *interf;
};

/**
 * operation system listener for interface events
 */
struct os_interface_listener {
  /*! name of the interface this listener is interested in */
  const char *name;

  /*! true if this interface needs to be a mesh interface */
  bool mesh;

  /**
   * Callback triggered when the interface changed
   * @param listener pointer to this listener
   * @return -1 if an error happened, and the listener should be
   *   triggered again later, 0 if everything was fine
   */
  int (*if_changed)(struct os_interface_listener *);

  /*! pointer to interface data */
  struct os_interface *data;

  /*! true if this listener still needs to process a change */
  bool _dirty;

  /*! hook to global list of listeners */
  struct list_entity _node;
};

/* prototypes for all os_system functions */
static INLINE struct os_interface *os_interface_add(struct os_interface_listener *);
static INLINE void os_interface_remove(struct os_interface_listener *);
static INLINE struct avl_tree *os_interface_get_tree(void);

static INLINE void os_interface_trigger_handler(struct os_interface_listener *);

static INLINE int os_interface_state_set(struct os_interface *, bool up);
static INLINE int os_interface_mac_set(struct os_interface *interf, struct netaddr *mac);

static INLINE int os_interface_address_set(struct os_interface_ip_change *addr);
static INLINE void os_interface_address_interrupt(struct os_interface_ip_change *addr);

static INLINE struct os_interface *os_interface_get_data_by_ifindex(unsigned ifindex);
static INLINE struct os_interface *os_interface_get_data_by_ifbaseindex(unsigned ifindex);
static INLINE const struct netaddr *os_interface_get_bindaddress(
  int af_type, struct netaddr_acl *filter, struct os_interface *ifdata);
static INLINE const struct os_interface_ip *os_interface_get_prefix_from_dst(
  struct netaddr *destination, struct os_interface *ifdata);

/* include os-specific headers */
#if defined(__linux__)
#include <oonf/base/os_linux/os_interface_linux.h>
#else
#error "Unknown operation system"
#endif

/**
 * @param ifname name of an interface
 * @return os interface instance, NULL if not registered
 */
static INLINE struct os_interface *
os_interface_get(const char *ifname) {
  struct os_interface *interf;
  return avl_find_element(os_interface_get_tree(), ifname, interf, _node);
}

#endif /* OS_INTERFACE_H_ */
