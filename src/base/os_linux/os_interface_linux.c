
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

/*! activate GUI sources for this file */
#define _GNU_SOURCE

/* must be first because of a problem with linux/rtnetlink.h */
#include <sys/socket.h>

/* and now the rest of the includes */
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/string.h>
#include <oonf/libcore/oonf_cfg.h>
#include <oonf/libcore/oonf_main.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_system.h>

#include <oonf/base/os_interface.h>

/* Definitions */
#define LOG_OS_INTERFACE _oonf_os_interface_subsystem.logging

/*! proc file entry for activating IPv4 forwarding */
#define PROC_IPFORWARD_V4 "/proc/sys/net/ipv4/ip_forward"

/*! proc file entry for activating IPv6 forwarding */
#define PROC_IPFORWARD_V6 "/proc/sys/net/ipv6/conf/all/forwarding"

/*! proc file entry to deactivate interface specific redirect requests */
#define PROC_IF_REDIRECT "/proc/sys/net/ipv4/conf/%s/send_redirects"

/*! proc file entry to deactivate generic redirect requests */
#define PROC_ALL_REDIRECT "/proc/sys/net/ipv4/conf/all/send_redirects"

/*! proc file entry to deactivate interface specific reverse path filter */
#define PROC_IF_SPOOF "/proc/sys/net/ipv4/conf/%s/rp_filter"

/*! proc file entry to deactivate generic reverse path filter */
#define PROC_ALL_SPOOF "/proc/sys/net/ipv4/conf/all/rp_filter"

/* prototypes */
static int _init(void);
static void _cleanup(void);
static void _early_cfg_init(void);

static struct os_interface *_add_interface(const char *name);
static void _remove_interface(struct os_interface *data);

static void _init_mesh(struct os_interface *os_if);
static void _refresh_mesh(struct os_interface *os_if, char *old_redirect, char *old_spoof);
static void _cleanup_mesh(struct os_interface *os_if);

static void _cb_rtnetlink_response(struct os_system_netlink_message *nl_msg, struct nlmsghdr *hdr);
static void _cb_rtnetlink_multicast(struct os_system_netlink *nl, struct nlmsghdr *hdr);
static void _cb_rtnetlink_feedback(struct os_system_netlink_message *nl_msg);

static void _activate_if_routing(void);
static void _deactivate_if_routing(void);
static int _os_linux_writeToFile(const char *file, char *old, char value);

static void _cb_delayed_interface_changed(struct oonf_timer_instance *);
static int _handle_unused_parameter(const char *arg);
static void _cb_cfg_changed(void);

/* subsystem configuration */
static struct cfg_schema_entry _interface_entries[] = {
  CFG_MAP_BOOL(os_interface, _internal.ignore_mesh, "ignore_mesh", "false", "Suppress os mesh interface configuration"),
};

static struct cfg_schema_section _interface_section = {
  CFG_OSIF_SCHEMA_INTERFACE_SECTION_INIT,
  .cb_delta_handler = _cb_cfg_changed,
  .entries = _interface_entries,
  .entry_count = ARRAYSIZE(_interface_entries),
};

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_SYSTEM_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_os_interface_subsystem = {
  .name = OONF_OS_INTERFACE_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .early_cfg_init = _early_cfg_init,
  .cfg_section = &_interface_section,
};
DECLARE_OONF_PLUGIN(_oonf_os_interface_subsystem);

static const uint32_t _rtnetlink_mcast[] = { RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR };

static struct os_system_netlink _rtnetlink_handler = {
  .name = "interface",
  .multicast = _rtnetlink_mcast,
  .multicast_count = ARRAYSIZE(_rtnetlink_mcast),
  
  .used_by = &_oonf_os_interface_subsystem,
  .cb_response = _cb_rtnetlink_response,
  .cb_multicast = _cb_rtnetlink_multicast,
  .cb_error = _cb_rtnetlink_feedback,
  .cb_done = _cb_rtnetlink_feedback,
};

static uint8_t nl_buffer1[256], nl_buffer2[256];
static struct os_system_netlink_message _nl_link_query = {
  .message = (struct nlmsghdr*)nl_buffer1,
  .max_length = ARRAYSIZE(nl_buffer1),
  .originator = &_rtnetlink_handler,
};
static struct os_system_netlink_message _nl_address_query = {
  .message = (struct nlmsghdr*)nl_buffer2,
  .max_length = ARRAYSIZE(nl_buffer2),
  .originator = &_rtnetlink_handler,
};

/* global procfile state before initialization */
static char _original_rp_filter;
static char _original_icmp_redirect;
static char _original_ipv4_forward;
static char _original_ipv6_forward;

/* counter of mesh interfaces for ip_forward configuration */
static int _mesh_count = 0;

/* kernel version check */
static bool _is_kernel_2_6_31_or_better;

/* interface data handling */
static struct oonf_class _interface_data_class = {
  .name = "network interface data",
  .size = sizeof(struct os_interface),
};

static struct oonf_class _interface_class = {
  .name = "network interface",
  .size = sizeof(struct os_interface_listener),
};

static struct oonf_class _interface_ip_class = {
  .name = "network interface ip",
  .size = sizeof(struct os_interface_ip),
};

static struct oonf_timer_class _interface_change_timer = {
  .name = "interface change",
  .callback = _cb_delayed_interface_changed,
};

static struct avl_tree _interface_data_tree;
static const char _ANY_INTERFACE[] = OS_INTERFACE_ANY;

/**
 * Initialize os-specific interface subsystem
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  struct nlmsghdr *msg;
  struct ifinfomsg *ifi;
  struct ifaddrmsg *ifa;

  if (os_system_linux_netlink_add(&_rtnetlink_handler, NETLINK_ROUTE)) {
    return -1;
  }

  avl_init(&_interface_data_tree, avl_comp_strcasecmp, false);
  oonf_class_add(&_interface_data_class);
  oonf_class_add(&_interface_ip_class);
  oonf_class_add(&_interface_class);
  oonf_timer_add(&_interface_change_timer);

  _is_kernel_2_6_31_or_better = os_system_linux_is_minimal_kernel(2, 6, 31);

  /* init link query */
  msg = (void *)&nl_buffer1[0];

  /* get link level data */
  memset(nl_buffer1, 0, sizeof(nl_buffer1));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  msg->nlmsg_type = RTM_GETLINK;

  /* set length of netlink message with ifinfomsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));

  ifi = NLMSG_DATA(msg);
  ifi->ifi_family = AF_NETLINK;

  /* init address query */
  msg = (void *)&nl_buffer2[0];

  /* get IP level data */
  memset(nl_buffer2, 0, sizeof(nl_buffer2));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  msg->nlmsg_type = RTM_GETADDR;

  /* set length of netlink message with ifaddrmsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(*ifa));

  ifa = NLMSG_DATA(msg);
  ifa->ifa_family = AF_UNSPEC;

  return 0;
}

/**
 * Cleanup os-specific interface subsystem
 */
static void
_cleanup(void) {
  struct os_interface_listener *if_listener, *if_listener_it;
  struct os_interface *os_if, *os_if_it;
  bool configured;

  avl_for_each_element_safe(&_interface_data_tree, os_if, _node, os_if_it) {
    configured = os_if->_internal.configured;
    list_for_each_element_safe(&os_if->_listeners, if_listener, _node, if_listener_it) {
      os_interface_linux_remove(if_listener);
    }

    if (configured) {
      os_if->_internal.configured = false;
      _remove_interface(os_if);
    }
  }

  oonf_timer_remove(&_interface_change_timer);
  oonf_class_remove(&_interface_ip_class);
  oonf_class_remove(&_interface_data_class);
  oonf_class_remove(&_interface_class);

  os_system_linux_netlink_remove(&_rtnetlink_handler);
}

/**
 * Handle pre-configuration work
 */
static void
_early_cfg_init(void) {
  oonf_main_set_parameter_handler(_handle_unused_parameter);
}

/**
 * Add an interface event listener to the operation system
 * @param if_listener network interface listener
 */
struct os_interface *
os_interface_linux_add(struct os_interface_listener *if_listener) {
  struct os_interface *data;

  if (if_listener->data) {
    /* interface is already hooked up to data */
    return if_listener->data;
  }

  if (!if_listener->name || !if_listener->name[0]) {
    if_listener->name = _ANY_INTERFACE;
  }

  data = _add_interface(if_listener->name);
  if (!data) {
    return NULL;
  }

  /* hook into interface data */
  if_listener->data = data;
  list_add_tail(&data->_listeners, &if_listener->_node);

  if (if_listener->mesh && if_listener->name != _ANY_INTERFACE) {
    if (data->_internal.mesh_counter == 0 && !data->_internal.ignore_mesh) {
      _init_mesh(data);
    }
    data->_internal.mesh_counter++;
  }

  /* trigger interface change listener if necessary */
  if_listener->_dirty = true;
  oonf_timer_start(&data->_change_timer, 200);

  return data;
}

/**
 * Remove an interface event listener to the operation system
 * @param if_listener network interface listener
 */
void
os_interface_linux_remove(struct os_interface_listener *if_listener) {
  struct os_interface *data;

  if (!if_listener->data) {
    /* interface not hooked up to data */
    return;
  }

  OONF_INFO(LOG_OS_INTERFACE, "Remove interface from tracking: %s", if_listener->name);

  if (if_listener->mesh) {
    if_listener->data->_internal.mesh_counter--;
    if (!if_listener->data->_internal.mesh_counter) {
      _cleanup_mesh(if_listener->data);
    }
  }

  /* unhook from interface data */
  data = if_listener->data;
  if_listener->data = NULL;
  list_remove(&if_listener->_node);

  /* remove interface if not used anymore */
  _remove_interface(data);
}

/**
 * @return tree of os interfaces
 */
struct avl_tree *
os_interface_linux_get_tree(void) {
  return &_interface_data_tree;
}

/**
 * Trigger the event handler of an interface listener
 * @param if_listener network interface listener
 */
void
os_interface_linux_trigger_handler(struct os_interface_listener *if_listener) {
  if_listener->_dirty = true;
  if (!oonf_timer_is_active(&if_listener->data->_change_timer)) {
    oonf_timer_start(&if_listener->data->_change_timer, OS_INTERFACE_CHANGE_TRIGGER_INTERVAL);
  }
}
/**
 * Set interface up or down
 * @param os_if network interface
 * @param up true if interface should be up, false if down
 * @return -1 if an error happened, 0 otherwise
 */
int
os_interface_linux_state_set(struct os_interface *os_if, bool up) {
  int oldflags;
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strscpy(ifr.ifr_name, os_if->name, IF_NAMESIZE);

  if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), SIOCGIFFLAGS, &ifr) < 0) {
    OONF_WARN(LOG_OS_INTERFACE, "ioctl SIOCGIFFLAGS (get flags) error on device %s: %s (%d)\n", os_if->name,
      strerror(errno), errno);
    return -1;
  }

  oldflags = ifr.ifr_flags;
  if (up) {
    ifr.ifr_flags |= IFF_UP;
  }
  else {
    ifr.ifr_flags &= ~IFF_UP;
  }

  if (oldflags == ifr.ifr_flags) {
    /* interface is already up/down */
    return 0;
  }

  if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), SIOCSIFFLAGS, &ifr) < 0) {
    OONF_WARN(LOG_OS_INTERFACE, "ioctl SIOCSIFFLAGS (set flags %s) error on device %s: %s (%d)\n", up ? "up" : "down",
      os_if->name, strerror(errno), errno);
    return -1;
  }
  return 0;
}

/**
 * Set or remove an IP address from an interface
 * @param addr interface address change request
 * @return -1 if the request could not be sent to the server,
 *   0 otherwise
 */
int
os_interface_linux_address_set(struct os_interface_ip_change *addr) {
  struct ifaddrmsg *ifaddrreq;
  struct nlmsghdr *msg;
#if defined(OONF_LOG_DEBUG_INFO)
  struct netaddr_str nbuf;
#endif

  /* get pointers for netlink message */
  addr->_internal.msg.message = (void *)addr->_internal.nl_buffer;
  addr->_internal.msg.max_length = sizeof(addr->_internal.nl_buffer);
  msg = addr->_internal.msg.message;
  
  memset(msg, 0, addr->_internal.msg.max_length);
  if (addr->set) {
    msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    msg->nlmsg_type = RTM_NEWADDR;
  }
  else {
    msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg->nlmsg_type = RTM_DELADDR;
  }

  /* set length of netlink message with ifaddrmsg payload */
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

  OONF_DEBUG(LOG_OS_INTERFACE, "%sset address on if %d: %s", addr->set ? "" : "re", addr->if_index,
    netaddr_to_string(&nbuf, &addr->address));

  ifaddrreq = NLMSG_DATA(msg);
  ifaddrreq->ifa_family = netaddr_get_address_family(&addr->address);
  ifaddrreq->ifa_prefixlen = netaddr_get_prefix_length(&addr->address);
  ifaddrreq->ifa_index = addr->if_index;
  ifaddrreq->ifa_scope = addr->scope;

  if (os_system_linux_netlink_addnetaddr(&addr->_internal.msg, IFA_LOCAL, &addr->address)) {
    return -1;
  }

  /* cannot fail */
  os_system_linux_netlink_send(&_rtnetlink_handler, &addr->_internal.msg);
  return 0;
}

/**
 * Stop processing an interface address change
 * @param addr interface address change request
 */
void
os_interface_linux_address_interrupt(struct os_interface_ip_change *addr) {
  if (list_is_node_added(&addr->_internal._node)) {
    /* remove first to prevent any kind of recursive cleanup */
    list_remove(&addr->_internal._node);

    if (addr->cb_finished) {
      addr->cb_finished(addr, -1);
    }
  }
}

/**
 * Set the mac address of an interface
 * @param os_if network interface
 * @param mac mac address
 * @return -1 if an error happened, 0 otherwise
 */
int
os_interface_linux_mac_set(struct os_interface *os_if, struct netaddr *mac) {
  struct ifreq if_req;
  struct netaddr_str nbuf;

  if (netaddr_get_address_family(mac) != AF_MAC48) {
    OONF_WARN(LOG_OS_INTERFACE, "Interface MAC must mac48, not %s", netaddr_to_string(&nbuf, mac));
    return -1;
  }

  memset(&if_req, 0, sizeof(if_req));
  strscpy(if_req.ifr_name, os_if->name, IF_NAMESIZE);

  if_req.ifr_addr.sa_family = ARPHRD_ETHER;
  netaddr_to_binary(&if_req.ifr_addr.sa_data, mac, 6);

  if (ioctl(os_system_linux_linux_get_ioctl_fd(AF_INET), SIOCSIFHWADDR, &if_req) < 0) {
    OONF_WARN(LOG_OS_INTERFACE, "Could not set mac address of '%s': %s (%d)", os_if->name, strerror(errno), errno);
    return -1;
  }
  return 0;
}

/**
 * Add an interface to the database if not already there
 * @param name interface name
 * @return interface representation, NULL if out of memory
 */
static struct os_interface *
_add_interface(const char *name) {
  struct os_interface *data;
  data = avl_find_element(&_interface_data_tree, name, data, _node);
  if (!data) {
    data = oonf_class_malloc(&_interface_data_class);
    if (!data) {
      return NULL;
    }

    OONF_INFO(LOG_OS_INTERFACE, "Add interface to tracking: %s", name);

    /* hook into interface data tree */
    strscpy(data->name, name, IF_NAMESIZE);
    data->_node.key = data->name;
    avl_insert(&_interface_data_tree, &data->_node);

    /* initialize list/tree */
    avl_init(&data->addresses, avl_comp_netaddr, false);
    avl_init(&data->peers, avl_comp_netaddr, false);
    list_init_head(&data->_listeners);

    /* initialize change timer */
    data->_change_timer.class = &_interface_change_timer;

    /* check if this is the unspecified interface "any" */
    if (strcmp(data->name, _ANY_INTERFACE) == 0) {
      data->flags.any = true;
      data->flags.up = true;
    }

    data->if_linklocal_v4 = &NETADDR_UNSPEC;
    data->if_linklocal_v6 = &NETADDR_UNSPEC;
    data->if_v4 = &NETADDR_UNSPEC;
    data->if_v6 = &NETADDR_UNSPEC;

    if (os_system_linux_netlink_is_done(&_nl_address_query)) {
      os_system_linux_netlink_send(&_rtnetlink_handler, &_nl_address_query);
    }
    if (os_system_linux_netlink_is_done(&_nl_link_query)) {
      os_system_linux_netlink_send(&_rtnetlink_handler, &_nl_link_query);
    }
  }

  return data;
}

/**
 * Remove an interface from the database if not used anymore
 * @param data interface representation
 */
static void
_remove_interface(struct os_interface *data) {
  struct os_interface_ip *ip, *ip_iter;

  if (!list_is_empty(&data->_listeners) || data->_internal.configured) {
    return;
  }

  if (data->flags.mesh) {
    _cleanup_mesh(data);
  }

  /* remove all addresses */
  avl_for_each_element_safe(&data->addresses, ip, _node, ip_iter) {
    avl_remove(&data->addresses, &ip->_node);
    oonf_class_free(&_interface_ip_class, ip);
  }
  avl_for_each_element_safe(&data->peers, ip, _node, ip_iter) {
    avl_remove(&data->peers, &ip->_node);
    oonf_class_free(&_interface_ip_class, ip);
  }

  /* stop change timer */
  oonf_timer_stop(&data->_change_timer);

  /* remove interface */
  avl_remove(&_interface_data_tree, &data->_node);
  oonf_class_free(&_interface_data_class, data);
}

/**
 * Initialize interface for mesh usage
 * @param os_if network interface data
 */
static void
_init_mesh(struct os_interface *os_if) {
  if (os_if->flags.loopback || os_if->flags.any) {
    /* ignore loopback and unspecific interface*/
    return;
  }

  if (os_if->flags.mesh) {
    /* mesh settings already active or not used for this interface */
    return;
  }
  os_if->flags.mesh = true;

  OONF_DEBUG(LOG_OS_INTERFACE, "Init mesh: %s", os_if->name);

  /* handle global ip_forward setting */
  _mesh_count++;
  if (_mesh_count == 1) {
    _activate_if_routing();
  }

  _refresh_mesh(os_if, &os_if->_internal._original_icmp_redirect, &os_if->_internal._original_ip_spoof);
}

static void
_refresh_mesh(struct os_interface *os_if, char *old_redirect, char *old_spoof) {
  char procfile[FILENAME_MAX];
  if (os_if->flags.loopback || os_if->flags.any) {
    /* ignore loopback and unspecific interface*/
    return;
  }

  if (!os_if->flags.mesh) {
    /* this is no mesh interface */
    return;
  }

  OONF_DEBUG(LOG_OS_INTERFACE, "Refresh mesh: %s", os_if->name);

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_REDIRECT, os_if->name);

  if (_os_linux_writeToFile(procfile, old_redirect, '0')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable ICMP redirects! "
                                "You should manually ensure that ICMP redirects are disabled!");
  }

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_SPOOF, os_if->name);

  if (_os_linux_writeToFile(procfile, old_spoof, '0')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable the IP spoof filter! "
                                "You should mannually ensure that IP spoof filtering is disabled!");
  }
}

/**
 * Cleanup interface after mesh usage
 * @param os_if network interface
 */
static void
_cleanup_mesh(struct os_interface *os_if) {
  char procfile[FILENAME_MAX];

  if (os_if->flags.loopback || os_if->flags.any) {
    /* ignore loopback and unspecific interface*/
    return;
  }

  if (!os_if->flags.mesh) {
    /* mesh settings not active */
    return;
  }

  OONF_DEBUG(LOG_OS_INTERFACE, "Cleanup mesh: %s", os_if->name);

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_REDIRECT, os_if->name);

  if (_os_linux_writeToFile(procfile, NULL, os_if->_internal._original_icmp_redirect) != 0) {
    OONF_WARN(LOG_OS_INTERFACE, "Could not restore ICMP redirect flag %s to %c", procfile,
      os_if->_internal._original_icmp_redirect);
  }

  /* Generate the procfile name */
  snprintf(procfile, sizeof(procfile), PROC_IF_SPOOF, os_if->name);

  if (_os_linux_writeToFile(procfile, NULL, os_if->_internal._original_ip_spoof) != 0) {
    OONF_WARN(
      LOG_OS_INTERFACE, "Could not restore IP spoof flag %s to %c", procfile, os_if->_internal._original_ip_spoof);
  }

  /* handle global ip_forward setting */
  _mesh_count--;
  if (_mesh_count == 0) {
    _deactivate_if_routing();
  }

  return;
}

/**
 * Set the required settings to allow multihop mesh routing
 */
static void
_activate_if_routing(void) {
  if (_os_linux_writeToFile(PROC_IPFORWARD_V4, &_original_ipv4_forward, '1')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not activate ip_forward for ipv4! "
                                "You should manually ensure that ip_forward for ipv4 is activated!");
  }
  if (os_system_is_ipv6_supported()) {
    if (_os_linux_writeToFile(PROC_IPFORWARD_V6, &_original_ipv6_forward, '1')) {
      OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not activate ip_forward for ipv6! "
                                  "You should manually ensure that ip_forward for ipv6 is activated!");
    }
  }

  if (_os_linux_writeToFile(PROC_ALL_REDIRECT, &_original_icmp_redirect, '0')) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable ICMP redirects! "
                                "You should manually ensure that ICMP redirects are disabled!");
  }

  /* check kernel version and disable global rp_filter */
  if (_is_kernel_2_6_31_or_better) {
    if (_os_linux_writeToFile(PROC_ALL_SPOOF, &_original_rp_filter, '0')) {
      OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not disable global rp_filter "
                                  "(necessary for kernel 2.6.31 and newer)! You should manually "
                                  "ensure that rp_filter is disabled!");
    }
  }
}

/**
 * Reset the multihop mesh routing settings to default
 */
static void
_deactivate_if_routing(void) {
  if (_os_linux_writeToFile(PROC_ALL_REDIRECT, NULL, _original_icmp_redirect) != 0) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not restore ICMP redirect flag %s to %c!", PROC_ALL_REDIRECT,
      _original_icmp_redirect);
  }

  if (_os_linux_writeToFile(PROC_ALL_SPOOF, NULL, _original_rp_filter)) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not restore global rp_filter flag %s to %c!", PROC_ALL_SPOOF,
      _original_rp_filter);
  }

  if (_os_linux_writeToFile(PROC_IPFORWARD_V4, NULL, _original_ipv4_forward)) {
    OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not restore %s to %c!", PROC_IPFORWARD_V4, _original_ipv4_forward);
  }
  if (os_system_is_ipv6_supported()) {
    if (_os_linux_writeToFile(PROC_IPFORWARD_V6, NULL, _original_ipv6_forward)) {
      OONF_WARN(LOG_OS_INTERFACE, "WARNING! Could not restore %s to %c", PROC_IPFORWARD_V6, _original_ipv6_forward);
    }
  }
}

/**
 * Overwrite a numeric entry in the procfile system and keep the old
 * value.
 * @param file pointer to filename (including full path)
 * @param old pointer to memory to store old value
 * @param value new value
 * @return -1 if an error happened, 0 otherwise
 */
static int
_os_linux_writeToFile(const char *file, char *old, char value) {
  int fd;
  char rv;

  if (value == 0) {
    /* ignore */
    return 0;
  }

  if ((fd = open(file, O_RDWR)) < 0) {
    OONF_WARN(LOG_OS_INTERFACE, "Error, cannot open proc entry %s: %s (%d)\n", file, strerror(errno), errno);
    return -1;
  }

  if (read(fd, &rv, 1) != 1) {
    OONF_WARN(LOG_OS_INTERFACE, "Error, cannot read proc entry %s: %s (%d)\n", file, strerror(errno), errno);
    close(fd);
    return -1;
  }

  if (rv != value) {
    if (lseek(fd, SEEK_SET, 0) == -1) {
      OONF_WARN(
        LOG_OS_INTERFACE, "Error, cannot rewind to start on proc entry %s: %s (%d)\n", file, strerror(errno), errno);
      close(fd);
      return -1;
    }

    if (write(fd, &value, 1) != 1) {
      OONF_WARN(
        LOG_OS_INTERFACE, "Error, cannot write '%c' to proc entry %s: %s (%d)\n", value, file, strerror(errno), errno);
    }

    OONF_DEBUG(LOG_OS_INTERFACE, "Writing '%c' (was %c) to %s", value, rv, file);
  }

  close(fd);

  if (old && rv != value) {
    *old = rv;
  }

  return 0;
}

/**
 * Trigger all change listeners of a network interface
 * @param os_if network interface
 */
static void
_trigger_if_change(struct os_interface *os_if) {
  struct os_interface_listener *if_listener;

  if (!oonf_timer_is_active(&os_if->_change_timer)) {
    /* inform listeners the interface changed */
    oonf_timer_start(&os_if->_change_timer, 200);

    list_for_each_element(&os_if->_listeners, if_listener, _node) {
      /* each interface should be informed */
      if_listener->_dirty = true;
    }
  }
}

/**
 * Trigger all change listeners of a network interface.
 * Trigger also all change listeners of the wildcard interface "any"
 * @param os_if network interface
 */
static void
_trigger_if_change_including_any(struct os_interface *os_if) {
  _trigger_if_change(os_if);

  os_if = avl_find_element(&_interface_data_tree, OS_INTERFACE_ANY, os_if, _node);
  if (os_if) {
    _trigger_if_change(os_if);
  }
}

/**
 * Parse an incoming LINK information from netlink
 * @param ifname interface name
 * @param msg netlink message
 */
static void
_link_parse_nlmsg(const char *ifname, struct nlmsghdr *msg) {
  struct ifinfomsg *ifi_msg;
  struct rtattr *ifi_attr;
  int ifi_len;
  struct netaddr addr;
  struct os_interface *ifdata;
  int iflink;
  bool old_up;
#if defined(OONF_LOG_DEBUG_INFO)
  struct netaddr_str nbuf;
#endif

  ifi_msg = NLMSG_DATA(msg);
  ifi_attr = (struct rtattr *)IFLA_RTA(ifi_msg);
  ifi_len = RTM_PAYLOAD(msg);

  ifdata = avl_find_element(&_interface_data_tree, ifname, ifdata, _node);
  if (!ifdata) {
    return;
  }

  old_up = ifdata->flags.up;
  ifdata->flags.up = (ifi_msg->ifi_flags & IFF_UP) != 0;
  ifdata->flags.promisc = (ifi_msg->ifi_flags & IFF_PROMISC) != 0;
  ifdata->flags.pointtopoint = (ifi_msg->ifi_flags & IFF_POINTOPOINT) != 0;
  ifdata->flags.loopback = (ifi_msg->ifi_flags & IFF_LOOPBACK) != 0;
  ifdata->flags.unicast_only = (ifi_msg->ifi_flags & IFF_MULTICAST) == 0;

  OONF_DEBUG(LOG_OS_INTERFACE, "Parse IFI_LINK %s (%u): %c%c%c%c%c", ifname, ifi_msg->ifi_index,
    ifdata->flags.up ? 'u' : '-', ifdata->flags.promisc ? 'p' : '-', ifdata->flags.pointtopoint ? 'P' : '-',
    ifdata->flags.loopback ? 'l' : '-', ifdata->flags.unicast_only ? 'U' : '-');

  ifdata->index = ifi_msg->ifi_index;
  ifdata->base_index = ifdata->index;

  if (!old_up && ifdata->flags.up && ifdata->flags.mesh && !ifdata->_internal.ignore_mesh) {
    /* refresh mesh parameters, might be gone for LTE-sticks */
    _refresh_mesh(ifdata, NULL, NULL);
  }
  for (; RTA_OK(ifi_attr, ifi_len); ifi_attr = RTA_NEXT(ifi_attr, ifi_len)) {
    switch (ifi_attr->rta_type) {
      case IFLA_ADDRESS:
        netaddr_from_binary(&addr, RTA_DATA(ifi_attr), RTA_PAYLOAD(ifi_attr), AF_MAC48);
        OONF_DEBUG(LOG_OS_INTERFACE, "Link: %s", netaddr_to_string(&nbuf, &addr));

        if (msg->nlmsg_type == RTM_NEWLINK) {
          memcpy(&ifdata->mac, &addr, sizeof(addr));
        }
        break;
      case IFLA_LINK:
        memcpy(&iflink, RTA_DATA(ifi_attr), RTA_PAYLOAD(ifi_attr));

        OONF_INFO(LOG_OS_INTERFACE, "Base interface index for %s (%u): %u", ifdata->name, ifdata->index, iflink);
        ifdata->base_index = iflink;
        break;
      default:
        // OONF_DEBUG(LOG_OS_INTERFACE, "ifi_attr_type: %u", ifi_attr->rta_type);
        break;
    }
  }

  if (!ifdata->_link_initialized) {
    ifdata->_link_initialized = true;
    OONF_INFO(LOG_OS_INTERFACE, "Interface %s link data initialized", ifdata->name);
  }
  _trigger_if_change_including_any(ifdata);
}

/**
 * Update the links for routable/ll addresses of a network interface
 * @param os_if network interface
 */
static void
_update_address_shortcuts(struct os_interface *os_if) {
  struct os_interface_ip *ip;
  bool ipv4_ll, ipv6_ll, ipv4_routable, ipv6_routable;
#if defined(OONF_LOG_DEBUG_INFO)
  struct netaddr_str nbuf;
#endif

  OONF_DEBUG(LOG_OS_INTERFACE, "Update address shortcuts for interface %s", os_if->name);

  /* update address shortcuts */
  os_if->if_v4 = &NETADDR_UNSPEC;
  os_if->if_v6 = &NETADDR_UNSPEC;
  os_if->if_linklocal_v4 = &NETADDR_UNSPEC;
  os_if->if_linklocal_v6 = &NETADDR_UNSPEC;

  avl_for_each_element(&os_if->addresses, ip, _node) {
    OONF_DEBUG(LOG_OS_INTERFACE, "Interface has %s", netaddr_to_string(&nbuf, &ip->address));
    ipv4_ll = netaddr_is_in_subnet(&NETADDR_IPV4_LINKLOCAL, &ip->address);
    ipv6_ll = netaddr_is_in_subnet(&NETADDR_IPV6_LINKLOCAL, &ip->address);

    ipv4_routable = !ipv4_ll && netaddr_get_address_family(&ip->address) == AF_INET &&
                    !netaddr_is_in_subnet(&NETADDR_IPV4_LOOPBACK_NET, &ip->address) &&
                    !netaddr_is_in_subnet(&NETADDR_IPV4_MULTICAST, &ip->address);
    ipv6_routable = !ipv6_ll && netaddr_get_address_family(&ip->address) == AF_INET6 &&
                    (netaddr_is_in_subnet(&NETADDR_IPV6_ULA, &ip->address) ||
                      netaddr_is_in_subnet(&NETADDR_IPV6_GLOBAL, &ip->address));

    if (netaddr_is_unspec(os_if->if_v4) && ipv4_routable) {
      OONF_DEBUG(LOG_OS_INTERFACE, "IPv4 is %s", netaddr_to_string(&nbuf, &ip->address));
      os_if->if_v4 = &ip->address;
    }
    if (netaddr_is_unspec(os_if->if_v6) && ipv6_routable) {
      OONF_DEBUG(LOG_OS_INTERFACE, "IPv6 is %s", netaddr_to_string(&nbuf, &ip->address));
      os_if->if_v6 = &ip->address;
    }
    if (netaddr_is_unspec(os_if->if_linklocal_v4) && ipv4_ll) {
      OONF_DEBUG(LOG_OS_INTERFACE, "Linklocal IPv4 is %s", netaddr_to_string(&nbuf, &ip->address));
      os_if->if_linklocal_v4 = &ip->address;
    }
    if (netaddr_is_unspec(os_if->if_linklocal_v6) && ipv6_ll) {
      OONF_DEBUG(LOG_OS_INTERFACE, "Linklocal IPv6 is %s", netaddr_to_string(&nbuf, &ip->address));
      os_if->if_linklocal_v6 = &ip->address;
    }
  }
}

/**
 * Add an IP address/prefix to a network interface
 * @param os_if network interface
 * @param prefixed_addr full IP address with prefix length
 * @param peer true if this is a peer address, false otherwise
 */
static void
_add_address(struct os_interface *os_if, struct netaddr *prefixed_addr, bool peer) {
  struct os_interface_ip *ip;
  struct avl_tree *tree;
#if defined(OONF_LOG_INFO)
  struct netaddr_str nbuf;
#endif

  tree = peer ? &os_if->peers : &os_if->addresses;

  ip = avl_find_element(tree, prefixed_addr, ip, _node);
  if (!ip) {
    ip = oonf_class_malloc(&_interface_ip_class);
    if (!ip) {
      return;
    }

    /* establish key and add to tree */
    memcpy(&ip->prefixed_addr, prefixed_addr, sizeof(*prefixed_addr));
    ip->_node.key = &ip->prefixed_addr;
    avl_insert(tree, &ip->_node);

    /* add back pointer */
    ip->interf = os_if;
  }

  OONF_INFO(LOG_OS_INTERFACE, "Add address to %s%s: %s", os_if->name, peer ? " (peer)" : "",
    netaddr_to_string(&nbuf, prefixed_addr));

  /* copy sanitized addresses */
  memcpy(&ip->address, prefixed_addr, sizeof(*prefixed_addr));
  netaddr_set_prefix_length(&ip->address, netaddr_get_maxprefix(&ip->address));
  netaddr_truncate(&ip->prefix, prefixed_addr);
}

/**
 * Remove an IP address/prefix from a network interface
 * @param os_if network interface
 * @param prefixed_addr full IP address with prefix length
 * @param peer true if this is a peer address, false otherwise
 */
static void
_remove_address(struct os_interface *os_if, struct netaddr *prefixed_addr, bool peer) {
  struct os_interface_ip *ip;
  struct avl_tree *tree;
#if defined(OONF_LOG_INFO)
  struct netaddr_str nbuf;
#endif

  tree = peer ? &os_if->peers : &os_if->addresses;
  ip = avl_find_element(tree, prefixed_addr, ip, _node);
  if (!ip) {
    return;
  }

  OONF_INFO(LOG_OS_INTERFACE, "Remove address from %s%s: %s", os_if->name, peer ? " (peer)" : "",
    netaddr_to_string(&nbuf, prefixed_addr));

  avl_remove(tree, &ip->_node);
  oonf_class_free(&_interface_ip_class, ip);
}

/**
 * Parse an incoming IP address information from netlink
 * @param ifname name of interface
 * @param msg netlink message
 */
static void
_address_parse_nlmsg(const char *ifname, struct nlmsghdr *msg) {
  struct ifaddrmsg *ifa_msg;
  struct rtattr *ifa_attr;
  int ifa_len;
  struct os_interface *ifdata;
  struct netaddr ifa_local, ifa_address;
  bool update;

  ifa_msg = NLMSG_DATA(msg);
  ifa_attr = IFA_RTA(ifa_msg);
  ifa_len = RTM_PAYLOAD(msg);

  ifdata = avl_find_element(&_interface_data_tree, ifname, ifdata, _node);
  if (!ifdata) {
    return;
  }

  OONF_DEBUG(LOG_OS_INTERFACE, "Parse IFA_GETADDR %s (%u) (len=%u)", ifname, ifa_msg->ifa_index, ifa_len);

  update = false;
  netaddr_invalidate(&ifa_local);
  netaddr_invalidate(&ifa_address);

  for (; RTA_OK(ifa_attr, ifa_len); ifa_attr = RTA_NEXT(ifa_attr, ifa_len)) {
    switch (ifa_attr->rta_type) {
      case IFA_ADDRESS:
        netaddr_from_binary_prefix(&ifa_address, RTA_DATA(ifa_attr), RTA_PAYLOAD(ifa_attr), 0, ifa_msg->ifa_prefixlen);
        if (netaddr_is_unspec(&ifa_local)) {
          memcpy(&ifa_local, &ifa_address, sizeof(ifa_local));
        }
        break;
      case IFA_LOCAL:
        netaddr_from_binary_prefix(&ifa_local, RTA_DATA(ifa_attr), RTA_PAYLOAD(ifa_attr), 0, ifa_msg->ifa_prefixlen);
        if (netaddr_is_unspec(&ifa_address)) {
          memcpy(&ifa_address, &ifa_local, sizeof(ifa_address));
        }
        break;
      default:
        OONF_DEBUG(LOG_OS_INTERFACE, "ifa_attr_type: %u", ifa_attr->rta_type);
        break;
    }
  }

  if (!netaddr_is_unspec(&ifa_local)) {
    if (msg->nlmsg_type == RTM_NEWADDR) {
      _add_address(ifdata, &ifa_local, false);
    }
    else {
      _remove_address(ifdata, &ifa_local, false);
    }

    _update_address_shortcuts(ifdata);
    update = true;
  }

  if (netaddr_cmp(&ifa_local, &ifa_address)) {
    if (msg->nlmsg_type == RTM_NEWADDR) {
      _add_address(ifdata, &ifa_address, true);
    }
    else {
      _remove_address(ifdata, &ifa_address, true);
    }

    update = true;
  }

  if (update) {
    if (!ifdata->_addr_initialized) {
      ifdata->_addr_initialized = true;
      OONF_INFO(LOG_OS_INTERFACE, "Interface %s address data initialized", ifdata->name);
    }
    _trigger_if_change_including_any(ifdata);
  }
}

/**
* Process a response to a netlink query
* @param nl_msg original netlink query
* @param hdr response of the kernel
*/
static void 
_cb_rtnetlink_response(struct os_system_netlink_message *nl_msg, struct nlmsghdr *hdr) {
  _cb_rtnetlink_multicast(nl_msg->originator, hdr);
}

/**
 * Handle incoming rtnetlink multicast messages for interface listeners
 * @param hdr pointer to netlink message
 */
static void
_cb_rtnetlink_multicast(struct os_system_netlink *nl __attribute__((unused)), struct nlmsghdr *hdr) {
  struct ifinfomsg *ifi;
  struct ifaddrmsg *ifa;
  char ifname[IF_NAMESIZE];

  if (hdr->nlmsg_type == RTM_NEWLINK || hdr->nlmsg_type == RTM_DELLINK) {
    ifi = (struct ifinfomsg *)NLMSG_DATA(hdr);
    if (!if_indextoname(ifi->ifi_index, ifname)) {
      return;
    }

    OONF_DEBUG(LOG_OS_INTERFACE, "Linkstatus of interface (%s) %d changed", ifname, ifi->ifi_index);
    _link_parse_nlmsg(ifname, hdr);
  }

  else if (hdr->nlmsg_type == RTM_NEWADDR || hdr->nlmsg_type == RTM_DELADDR) {
    ifa = (struct ifaddrmsg *)NLMSG_DATA(hdr);
    if (!if_indextoname(ifa->ifa_index, ifname)) {
      return;
    }

    OONF_DEBUG(LOG_OS_INTERFACE, "Address of interface %s (%u) changed", ifname, ifa->ifa_index);
    _address_parse_nlmsg(ifname, hdr);
  }
  else {
    OONF_WARN(LOG_OS_INTERFACE, "Message type: %u", hdr->nlmsg_type);
  }
}

/**
 * Handle feedback from netlink socket
 * @param nl_msg netlink message we got feedback/timeout for
 */
static void
_cb_rtnetlink_feedback(struct os_system_netlink_message *nl_msg) {
  struct os_interface_ip_change *addr;

  OONF_INFO(LOG_OS_INTERFACE, "Netlink socket provided feedback: %d %d", 
            nl_msg->message->nlmsg_seq, nl_msg->result);
  if (nl_msg->dump) {
    /* this was one of the queries, no need to react */
    return;
  }

  addr = container_of(nl_msg, struct os_interface_ip_change, _internal.msg);
  if (list_is_node_added(&addr->_internal._node)) {
    /* remove first to prevent any kind of recursive cleanup */
    list_remove(&addr->_internal._node);

    if (addr->cb_finished) {
      addr->cb_finished(addr, nl_msg->result);
    }
  }
}

/**
 * Handle timer that announces interface state/address changes
 * @param timer timer instance
 */
static void
_cb_delayed_interface_changed(struct oonf_timer_instance *timer) {
  struct os_interface *data;
  struct os_interface_listener *interf, *interf_it;
  bool error;

  data = container_of(timer, struct os_interface, _change_timer);

  if (!data->flags.any && (!data->_link_initialized || !data->_addr_initialized)) {
    /* wait until we have all the data */
    return;
  }

  OONF_INFO(LOG_OS_INTERFACE, "Interface %s (%u) changed", data->name, data->index);

  error = false;
  list_for_each_element_safe(&data->_listeners, interf, _node, interf_it) {
    if (!interf->_dirty) {
      continue;
    }

    if (interf->if_changed && interf->if_changed(interf)) {
      /* interface change handler had a problem and wants to re-trigger */
      error = true;
    }
    else {
      /* everything fine, job done */
      interf->_dirty = false;
    }
  }

  if (error) {
    /* re-trigger */
    oonf_timer_start(timer, 200);
  }
}

/**
 * Transform remaining parameters into interface sections
 * @param arg command line parameter
 * @return always 0 (ok)
 */
static int
_handle_unused_parameter(const char *arg) {
  const char *ifname;
  char ifbuf[IF_NAMESIZE];

  ifname = cfg_get_phy_if(ifbuf, arg);

  cfg_db_add_namedsection(oonf_cfg_get_rawdb(), _interface_section.type, ifname);
  return 0;
}

/**
 * configuration of interface section changed
 */
static void
_cb_cfg_changed(void) {
  struct os_interface *data;
  int result;

  /* get pointer to interface if available */
  data = avl_find_element(&_interface_data_tree, _interface_section.section_name, data, _node);

  if (_interface_section.post && !data) {
    /* make sure interface data is available */
    data = _add_interface(_interface_section.section_name);
    if (!data) {
      return;
    }
  }

  /* overwrite settings */
  if (data) {
    result = cfg_schema_tobin(data, _interface_section.post, _interface_entries, ARRAYSIZE(_interface_entries));
    if (result) {
      OONF_WARN(LOG_OS_INTERFACE, "Could not convert %s '%s' to binary (%d)", _interface_section.type, data->name,
        -(result + 1));
      return;
    }
  }

  if (!_interface_section.post) {
    /* try to remove old interface */
    if (data) {
      data->_internal.configured = false;

      if (!data->_internal.ignore_mesh && data->_internal.mesh_counter > 0) {
        /* reactivate mesh settings */
        _cleanup_mesh(data);
      }

      /* remove allocated instance (if no listener is left) */
      _remove_interface(data);
    }
    return;
  }

  /* mark interface as configured */
  data->_internal.configured = true;

  if (data->_internal.ignore_mesh || data->_internal.mesh_counter == 0) {
    /* restore original os mesh configuration if necessary */
    _cleanup_mesh(data);
  }
  else {
    /* set os mesh configuration if necessary */
    _init_mesh(data);
  }
}
