
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

#include <errno.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_socket.h>
#include <oonf/base/os_fd.h>
#include <oonf/base/os_interface.h>

/* Defintions */
#define LOG_PACKET _oonf_packet_socket_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _handle_errno1(struct oonf_packet_socket *pktsocket, union netaddr_socket *remote);

static void _packet_add(struct oonf_packet_socket *pktsocket, union netaddr_socket *local, struct os_interface *os_if);
static int _apply_managed(struct oonf_packet_managed *managed);
static int _apply_managed_socketpair(int af_type, struct oonf_packet_managed *managed, struct os_interface *os_if,
  bool *changed, struct oonf_packet_socket *sock, struct oonf_packet_socket *mc_sock, struct netaddr *mc_ip);
static int _apply_managed_socket(struct oonf_packet_managed *managed, struct oonf_packet_socket *stream,
  const struct netaddr *bindto, int port, uint8_t dscp, int protocol, struct os_interface *os_if);
static void _cb_packet_event_unicast(struct oonf_socket_entry *);
static void _cb_packet_event_multicast(struct oonf_socket_entry *);
static void _cb_packet_event(struct oonf_socket_entry *, bool mc);
static int _cb_interface_listener(struct os_interface_listener *l);

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_SOCKET_SUBSYSTEM,
  OONF_OS_FD_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_packet_socket_subsystem = {
  .name = OONF_PACKET_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_packet_socket_subsystem);

/* other global variables */
static struct list_entity _packet_sockets = { NULL, NULL };
static char _input_buffer[65536];

/**
 * Initialize packet socket handler
 * @return always returns 0
 */
static int
_init(void) {
  list_init_head(&_packet_sockets);
  return 0;
}

/**
 * Cleanup all resources allocated by packet socket handler
 */
static void
_cleanup(void) {
  struct oonf_packet_socket *skt;

  while (!list_is_empty(&_packet_sockets)) {
    skt = list_first_element(&_packet_sockets, skt, node);

    oonf_packet_remove(skt, true);
  }
}

/**
 * Add a new packet socket handler
 * @param pktsocket pointer to an initialized packet socket struct
 * @param local pointer local IP address of packet socket
 * @param os_if pointer to interface to bind socket on, NULL
 *   if socket should not be bound to interface
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_packet_add(struct oonf_packet_socket *pktsocket, union netaddr_socket *local, struct os_interface *os_if) {
  /* Init socket */
  if (os_fd_getsocket(&pktsocket->scheduler_entry.fd, local, false, 0, os_if, LOG_PACKET)) {
    return -1;
  }

  _packet_add(pktsocket, local, os_if);
  return 0;
}

/**
 * Add a new raw packet socket handler
 * @param pktsocket pointer to an initialized packet socket struct
 * @param protocol IP protocol number
 * @param local pointer local IP address of packet socket
 * @param interf pointer to interface to bind socket on, NULL
 *   if socket should not be bound to interface
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_packet_raw_add(
  struct oonf_packet_socket *pktsocket, int protocol, union netaddr_socket *local, struct os_interface *interf) {
  /* Init socket */
  if (os_fd_getrawsocket(&pktsocket->scheduler_entry.fd, local, false, 0, interf, LOG_PACKET)) {
    return -1;
  }

  _packet_add(pktsocket, local, interf);
  pktsocket->protocol = protocol;
  return 0;
}

static void
_packet_add(struct oonf_packet_socket *pktsocket, union netaddr_socket *local, struct os_interface *interf) {
  struct netaddr_str nbuf;

  pktsocket->os_if = interf;
  pktsocket->scheduler_entry.name = pktsocket->socket_name;
  pktsocket->scheduler_entry.process = _cb_packet_event_unicast;

  abuf_init(&pktsocket->out);
  list_add_tail(&_packet_sockets, &pktsocket->node);
  memcpy(&pktsocket->local_socket, local, sizeof(pktsocket->local_socket));

  /* generate socket name */
  snprintf(pktsocket->socket_name, sizeof(pktsocket->socket_name), "udp: %s",
    netaddr_socket_to_string(&nbuf, &pktsocket->local_socket));

  pktsocket->_errno1_measurement_time = oonf_clock_getNow();

  if (pktsocket->config.input_buffer_length == 0) {
    pktsocket->config.input_buffer = _input_buffer;
    pktsocket->config.input_buffer_length = sizeof(_input_buffer);
  }

  oonf_socket_add(&pktsocket->scheduler_entry);
  oonf_socket_set_read(&pktsocket->scheduler_entry, true);
}

/**
 * Remove a packet socket from the global scheduler
 * @param pktsocket pointer to packet socket
 * @param force true if the socket should be removed instantly,
 *   false if it should be removed after the last packet in queue is sent
 */
void
oonf_packet_remove(struct oonf_packet_socket *pktsocket, bool force __attribute__((unused))) {
  // TODO: implement non-force behavior for UDP sockets
  if (list_is_node_added(&pktsocket->node)) {
    oonf_socket_remove(&pktsocket->scheduler_entry);
    os_fd_close(&pktsocket->scheduler_entry.fd);
    abuf_free(&pktsocket->out);

    list_remove(&pktsocket->node);
  }
}

/**
 * Send a data packet through a packet socket. The transmission might not
 * be happen synchronously if the socket would block.
 * @param pktsocket pointer to packet socket
 * @param remote ip/address to send packet to
 * @param data pointer to data to be sent
 * @param length length of data
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_packet_send(struct oonf_packet_socket *pktsocket, union netaddr_socket *remote, const void *data, size_t length) {
  int result;
  struct netaddr_str buf;

  if (abuf_getlen(&pktsocket->out) == 0) {
    /* no backlog of outgoing packets, try to send directly */
    result = os_fd_sendto(&pktsocket->scheduler_entry.fd, data, length, remote, pktsocket->config.dont_route);
    if (result > 0) {
      /* successful */
      OONF_DEBUG(LOG_PACKET, "Sent %d bytes to %s %s", result, netaddr_socket_to_string(&buf, remote),
        pktsocket->os_if != NULL ? pktsocket->os_if->name : "");
      oonf_socket_register_direct_send(&pktsocket->scheduler_entry);
      return 0;
    }

    if (errno == EPERM) {
      _handle_errno1(pktsocket, remote);
      return -1;
    }
    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
      OONF_WARN(LOG_PACKET, "Cannot send UDP packet to %s: %s (%d)", netaddr_socket_to_string(&buf, remote),
        strerror(errno), errno);
      return -1;
    }
  }

  /* append destination */
  abuf_memcpy(&pktsocket->out, remote, sizeof(*remote));

  /* append data length */
  abuf_append_uint16(&pktsocket->out, length);

  /* append data */
  abuf_memcpy(&pktsocket->out, data, length);

  /* activate outgoing socket scheduler */
  oonf_socket_set_write(&pktsocket->scheduler_entry, true);
  return 0;
}

/**
 * Initialize a new managed packet socket
 * @param managed pointer to packet socket
 */
void
oonf_packet_add_managed(struct oonf_packet_managed *managed) {
  if (managed->config.input_buffer_length == 0) {
    managed->config.input_buffer = _input_buffer;
    managed->config.input_buffer_length = sizeof(_input_buffer);
  }

  managed->_if_listener.if_changed = _cb_interface_listener;
  managed->_if_listener.name = managed->_managed_config.interface;
  managed->_if_listener.mesh = managed->_managed_config.mesh;
}

/**
 * Cleanup an initialized managed packet socket
 * @param managed pointer to packet socket
 * @param forced true if socket should be closed instantly
 */
void
oonf_packet_remove_managed(struct oonf_packet_managed *managed, bool forced) {
  oonf_packet_remove(&managed->socket_v4, forced);
  oonf_packet_remove(&managed->socket_v6, forced);
  oonf_packet_remove(&managed->multicast_v4, forced);
  oonf_packet_remove(&managed->multicast_v6, forced);

  os_interface_remove(&managed->_if_listener);
  oonf_packet_free_managed_config(&managed->_managed_config);
}

/**
 * Apply a new configuration to a managed socket. This might close and
 * reopen sockets because of changed binding IPs or ports.
 * @param managed pointer to managed packet socket
 * @param config pointer to new configuration
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_packet_apply_managed(struct oonf_packet_managed *managed, const struct oonf_packet_managed_config *config) {
  bool if_changed;
  int result;

  if_changed = strcmp(config->interface, managed->_managed_config.interface) != 0 ||
               !list_is_node_added(&managed->_if_listener._node);

  oonf_packet_copy_managed_config(&managed->_managed_config, config);

  /* handle change in interface listener */
  if (if_changed) {
    /* interface changed, remove old listener if necessary */
    os_interface_remove(&managed->_if_listener);

    /* create new interface listener */
    managed->_if_listener.name = managed->_managed_config.interface;
    managed->_if_listener.mesh = managed->_managed_config.mesh;
    os_interface_add(&managed->_if_listener);
  }

  OONF_DEBUG(LOG_PACKET, "Apply changes for managed socket (if %s) with port %d/%d",
    config->interface[0] == 0 ? "any" : config->interface, config->port, config->multicast_port);

  result = _apply_managed(managed);
  if (result) {
    /* did not work, trigger interface handler to try later again */
    os_interface_trigger_handler(&managed->_if_listener);
  }
  return result;
}

/**
 * Send a packet out over one of the managed sockets, depending on the
 * address family type of the remote address
 * @param managed pointer to managed packet socket
 * @param remote pointer to remote socket
 * @param data pointer to data to send
 * @param length length of data
 * @return -1 if an error happened, 0 if packet was sent, 1 if this
 *    type of address was switched off
 */
int
oonf_packet_send_managed(
  struct oonf_packet_managed *managed, union netaddr_socket *remote, const void *data, size_t length) {
  int result;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  if (netaddr_socket_get_addressfamily(remote) == AF_UNSPEC) {
    return 0;
  }

  result = 1;
  errno = 0;
  if (list_is_node_added(&managed->socket_v4.scheduler_entry._node) &&
      netaddr_socket_get_addressfamily(remote) == AF_INET) {
    result = oonf_packet_send(&managed->socket_v4, remote, data, length);
  }
  if (list_is_node_added(&managed->socket_v6.scheduler_entry._node) &&
      netaddr_socket_get_addressfamily(remote) == AF_INET6) {
    result = oonf_packet_send(&managed->socket_v6, remote, data, length);
  }
  else {
    OONF_DEBUG(LOG_PACKET, "Managed socket did not sent packet to %s because socket was not active",
      netaddr_socket_to_string(&buf, remote));
  }

  if (errno == EBADF) {
    /* file descriptor is not working anymore */
    if (netaddr_socket_get_addressfamily(remote) == AF_INET) {
      oonf_packet_remove(&managed->socket_v4, true);
    }
    else {
      oonf_packet_remove(&managed->socket_v6, true);
    }

    /* try to re-open */
    _apply_managed(managed);
  }
  return result;
}

/**
 * Send a packet out over one of the managed sockets, depending on the
 * address family type of the remote address
 * @param managed pointer to managed packet socket
 * @param data pointer to data to send
 * @param length length of data
 * @param af_type address family to send multicast
 * @return -1 if an error happened, 0 if packet was sent, 1 if this
 *    type of address was switched off
 */
int
oonf_packet_send_managed_multicast(struct oonf_packet_managed *managed, const void *data, size_t length, int af_type) {
  if (af_type == AF_INET) {
    return oonf_packet_send_managed(managed, &managed->multicast_v4.local_socket, data, length);
  }
  else if (af_type == AF_INET6) {
    return oonf_packet_send_managed(managed, &managed->multicast_v6.local_socket, data, length);
  }
  errno = 0;
  return 1;
}

/**
 * Returns true if the socket for IPv4/6 is active to send data.
 * @param managed pointer to managed UDP socket
 * @param af_type address familty
 * @return true if the selected socket is active.
 */
bool
oonf_packet_managed_is_active(struct oonf_packet_managed *managed, int af_type) {
  switch (af_type) {
    case AF_INET:
      return oonf_packet_is_active(&managed->socket_v4);
    case AF_INET6:
      return oonf_packet_is_active(&managed->socket_v6);
    default:
      return false;
  }
}

/**
 * copies a packet managed configuration object
 * @param dst Destination
 * @param src Source
 */
void
oonf_packet_copy_managed_config(struct oonf_packet_managed_config *dst, const struct oonf_packet_managed_config *src) {
  oonf_packet_free_managed_config(dst);

  /* careful, we are doing a shallow copy, so both ACLs are BAD after this */
  memcpy(dst, src, sizeof(*dst));

  /* fix it to make sure we don't use-after-free or double-free */
  memset(&dst->acl, 0, sizeof(dst->acl));
  memset(&dst->bindto, 0, sizeof(dst->bindto));

  /* now do a deep copy of the ACLs */
  netaddr_acl_copy(&dst->acl, &src->acl);
  netaddr_acl_copy(&dst->bindto, &src->bindto);
}

/**
 * Free dynamically allocated parts of managed packet configuration
 * @param config packet configuration
 */
void
oonf_packet_free_managed_config(struct oonf_packet_managed_config *config) {
  netaddr_acl_remove(&config->acl);
  netaddr_acl_remove(&config->bindto);
}

/**
 * Handle rate limitation of errno==1 warnings
 * @param pktsocket packet socket the error happened
 * @param remote target of UDP packet
 */
static void
_handle_errno1(struct oonf_packet_socket *pktsocket, union netaddr_socket *remote) {
  int64_t interval;
  uint32_t count, normalized;
  struct netaddr_str buf;
  const char *ifname = "-";
  bool triggered;

  /* we do a rate limitation for EPERM */
  interval = -oonf_clock_get_relative(pktsocket->_errno1_measurement_time);
  count = pktsocket->_errno1_count;
  normalized = count;
  if (interval >= 60000) {
    normalized /= (interval / 60000);
  }

  /* increase error counter */
  pktsocket->_errno1_count++;

  triggered = false;
  if (interval >= 60000 && pktsocket->_errno1_suppression && normalized < 5) {
    /* switch suppression on */
    pktsocket->_errno1_suppression = false;
  }
  else if (!pktsocket->_errno1_suppression && normalized > 10) {
    /* switch suppression off */
    pktsocket->_errno1_suppression = true;
    count = 0;
    triggered = true;
  }

  if (interval >= 60000 || triggered) {
    /* start new measurement interval */
    pktsocket->_errno1_measurement_time = oonf_clock_getNow();
    pktsocket->_errno1_count = 1;
  }

  if (pktsocket->os_if) {
    /* remember interface name */
    ifname = pktsocket->os_if->name;
  }

  if (pktsocket->_errno1_suppression && count != 0) {
    if (pktsocket->_errno1_count > 1) {
      /* suppress warning */
      return;
    }

    OONF_WARN(LOG_PACKET, "Cannot send UDP packet to %s (%s): %s (%d) (%d similar errors suppressed)",
      netaddr_socket_to_string(&buf, remote), ifname, strerror(errno), errno, count);
  }
  else {
    OONF_WARN(LOG_PACKET, "Cannot send UDP packet to %s (%s): %s (%d)", netaddr_socket_to_string(&buf, remote), ifname,
      strerror(errno), errno);
  }
}

/**
 * Apply a new configuration to all attached sockets
 * @param managed pointer to managed socket
 * @return -1 if an error happened, 0 otherwise
 */
static int
_apply_managed(struct oonf_packet_managed *managed) {
  struct os_interface *os_if = NULL;
  bool changed = false;
  int result = 0;

  /* get interface */
  if (managed->_if_listener.name) {
    os_if = managed->_if_listener.data;
  }

  if (_apply_managed_socketpair(AF_INET, managed, os_if, &changed, &managed->socket_v4, &managed->multicast_v4,
        &managed->_managed_config.multicast_v4)) {
    result = -1;
  }

  if (_apply_managed_socketpair(AF_INET6, managed, os_if, &changed, &managed->socket_v6, &managed->multicast_v6,
        &managed->_managed_config.multicast_v6)) {
    result = -1;
  }

  if (managed->cb_settings_change) {
    managed->cb_settings_change(managed, changed);
  }
  return result;
}

/**
 * Apply a new configuration to an unicast/multicast socket pair
 * @param managed managed socket
 * @param os_if OS interface to bind sockets, NULL if unbound socket
 * @param changed buffer for boolean, will be set to true if sockets changed
 * @param sock unicast packet socket
 * @param mc_sock pointer to multicast packet socket
 * @param mc_ip multicast address
 * @return 0 if okay, -1 if an error happened
 */
static int
_apply_managed_socketpair(int af_type, struct oonf_packet_managed *managed, struct os_interface *os_if, bool *changed,
  struct oonf_packet_socket *sock, struct oonf_packet_socket *mc_sock, struct netaddr *mc_ip) {
  struct netaddr_acl *bind_ip_acl;
  int sockstate = 0, result = 0;
  uint16_t mc_port;
  bool real_multicast;
  const struct netaddr *bind_ip;

  bind_ip_acl = &managed->_managed_config.bindto;

  /* copy unicast port if necessary */
  mc_port = managed->_managed_config.multicast_port;
  if (mc_port == 0) {
    mc_port = managed->_managed_config.port;
  }

  /* Get address the unicast socket should bind on */
  if (os_if != NULL && !os_if->flags.up) {
    bind_ip = NULL;
  }
  else if (os_if != NULL && netaddr_get_address_family(os_if->if_linklocal_v6) == af_type &&
           netaddr_acl_check_accept(bind_ip_acl, os_if->if_linklocal_v6)) {
    bind_ip = os_if->if_linklocal_v6;
  }
  else if (os_if != NULL && netaddr_get_address_family(os_if->if_linklocal_v4) == af_type &&
           netaddr_acl_check_accept(bind_ip_acl, os_if->if_linklocal_v4)) {
    bind_ip = os_if->if_linklocal_v4;
  }
  else {
    bind_ip = os_interface_get_bindaddress(af_type, bind_ip_acl, os_if);
  }
  if (!bind_ip) {
    oonf_packet_remove(sock, false);
    oonf_packet_remove(mc_sock, false);
    return 0;
  }

  /* handle loopback interface */
  if (os_if != NULL && os_if->flags.loopback && netaddr_get_address_family(mc_ip) != AF_UNSPEC) {
    memcpy(mc_ip, bind_ip, sizeof(*mc_ip));
  }

  /* check if multicast IP is a real multicast (and not a broadcast) */
  real_multicast = netaddr_is_in_subnet(
    netaddr_get_address_family(mc_ip) == AF_INET ? &NETADDR_IPV4_MULTICAST : &NETADDR_IPV6_MULTICAST, mc_ip);

  sockstate = _apply_managed_socket(managed, sock, bind_ip, managed->_managed_config.port,
    managed->_managed_config.dscp, managed->_managed_config.rawip ? managed->_managed_config.protocol : 0, os_if);
  if (sockstate == 0) {
    /* settings really changed */
    *changed = true;

    if (real_multicast && os_if != NULL && os_if->flags.up) {
      os_fd_join_mcast_send(&sock->scheduler_entry.fd, mc_ip, os_if, managed->_managed_config.loop_multicast,
        managed->_managed_config.ttl_multicast, LOG_PACKET);
    }
  }
  else if (sockstate < 0) {
    /* error */
    result = -1;
    oonf_packet_remove(sock, true);
  }

  if (real_multicast && netaddr_get_address_family(mc_ip) != AF_UNSPEC) {
    /* multicast */
    sockstate = _apply_managed_socket(managed, mc_sock, mc_ip, mc_port, managed->_managed_config.dscp,
      managed->_managed_config.rawip ? managed->_managed_config.protocol : 0, os_if);
    if (sockstate == 0) {
      /* settings really changed */
      *changed = true;

      mc_sock->scheduler_entry.process = _cb_packet_event_multicast;

      /* join multicast group */
      os_fd_join_mcast_recv(&mc_sock->scheduler_entry.fd, mc_ip, os_if, LOG_PACKET);
    }
    else if (sockstate < 0) {
      /* error */
      result = -1;
      oonf_packet_remove(sock, true);
    }
  }
  else {
    oonf_packet_remove(mc_sock, true);

    /*
     * initialize anyways because we use it for sending broadcasts with
     * oonf_packet_send_managed_multicast()
     */
    netaddr_socket_init(&mc_sock->local_socket, mc_ip, mc_port, os_if == NULL ? 0 : os_if->index);
  }
  return result;
}

/**
 * Apply new configuration to a managed stream socket
 * @param managed managed packet socket (pair)
 * @param packet packet socket
 * @param bindto local address to bind socket to
 *   set to AF_UNSPEC for simple reinitialization
 * @param port local port number
 * @param dscp dscp value for outgoing traffic
 * @param protocol IP protocol for raw IP socket, 0 otherwise
 * @param data interface data to bind socket to, might be NULL
 * @return -1 if an error happened, 0 if everything is okay,
 *   1 if the socket wasn't touched.
 */
static int
_apply_managed_socket(struct oonf_packet_managed *managed, struct oonf_packet_socket *packet,
  const struct netaddr *bindto, int port, uint8_t dscp, int protocol, struct os_interface *data) {
  union netaddr_socket sock;
  struct netaddr_str buf;

  /* create binding socket */
  if (netaddr_socket_init(&sock, bindto, port, data == NULL ? 0 : data->index)) {
    OONF_WARN(LOG_PACKET, "Cannot create managed socket address: %s/%u", netaddr_to_string(&buf, bindto), port);
    return -1;
  }

  if (list_is_node_added(&packet->node)) {
    if (data == packet->os_if && memcmp(&sock, &packet->local_socket, sizeof(sock)) == 0
      && protocol == packet->protocol) {
      /* nothing changed, just copy config again */
      memcpy(&packet->config, &managed->config, sizeof(packet->config));
      return 1;
    }
  }
  else {
    if (data != NULL && !data->flags.up) {
      /* nothing changed */
      return 1;
    }
  }

  /* remove old socket */
  oonf_packet_remove(packet, true);

  if (data != NULL && !data->flags.up) {
    OONF_DEBUG(LOG_PACKET, "Interface %s of socket is down", data->name);
    return 0;
  }

  /* copy configuration */
  memcpy(&packet->config, &managed->config, sizeof(packet->config));
  if (packet->config.user == NULL) {
    packet->config.user = managed;
  }

  /* create new socket */
  if (protocol) {
    if (oonf_packet_raw_add(packet, protocol, &sock, data)) {
      return -1;
    }
  }
  else {
    if (oonf_packet_add(packet, &sock, data)) {
      return -1;
    }
  }

  if (os_fd_set_dscp(&packet->scheduler_entry.fd, dscp, netaddr_get_address_family(bindto) == AF_INET6)) {
    OONF_WARN(LOG_PACKET, "Could not set DSCP value for socket: %s (%d)", strerror(errno), errno);
    oonf_packet_remove(packet, true);
    return -1;
  }
  packet->os_if = data;

  OONF_DEBUG(LOG_PACKET, "Opened new socket and bound it to %s (if %s)", netaddr_to_string(&buf, bindto),
    data != NULL ? data->name : "any");
  return 0;
}

/**
 * callback for unicast events in socket scheduler
 * @param entry socket entry that fired event
 */
static void
_cb_packet_event_unicast(struct oonf_socket_entry *entry) {
  _cb_packet_event(entry, false);
}

/**
 * callback for multicast events in socket scheduler
 * @param entry socket entry that fired event
 */
static void
_cb_packet_event_multicast(struct oonf_socket_entry *entry) {
  _cb_packet_event(entry, true);
}

/**
 * Callback to handle data from the olsr socket scheduler
 * @param entry socket entry that fired event
 * @param multicast true if the multicast socket fired the event,
 *   false otherwise
 */
static void
_cb_packet_event(struct oonf_socket_entry *entry, bool multicast __attribute__((unused))) {
  struct oonf_packet_socket *pktsocket;
  union netaddr_socket sock;
  uint16_t length;
  char *pkt;
  ssize_t result;
  struct netaddr_str netbuf;

#ifdef OONF_LOG_DEBUG_INFO
  const char *interf = "";
#endif

  pktsocket = container_of(entry, typeof(*pktsocket), scheduler_entry);

#ifdef OONF_LOG_DEBUG_INFO
  if (pktsocket->os_if) {
    interf = pktsocket->os_if->name;
  }
#endif

  if (oonf_socket_is_read(entry)) {
    uint8_t *buf;

    /* clear recvfrom memory */
    memset(&sock, 0, sizeof(sock));

    /* handle incoming data */
    buf = pktsocket->config.input_buffer;

    result = os_fd_recvfrom(&entry->fd, buf, pktsocket->config.input_buffer_length - 1, &sock, pktsocket->os_if);
    if (result > 0 && pktsocket->config.receive_data != NULL) {
      /* handle raw socket */
      if (pktsocket->protocol) {
        buf = os_fd_skip_rawsocket_prefix(buf, &result, pktsocket->local_socket.std.sa_family);
        if (!buf) {
          OONF_WARN(LOG_PACKET, "Error while skipping IP header for socket %s:",
            netaddr_socket_to_string(&netbuf, &pktsocket->local_socket));
          return;
        }
      }
      /* null terminate it */
      buf[result] = 0;

      /* received valid packet */
      OONF_DEBUG(LOG_PACKET, "Received %" PRINTF_SSIZE_T_SPECIFIER " bytes from %s %s (%s)", result,
        netaddr_socket_to_string(&netbuf, &sock), interf, multicast ? "multicast" : "unicast");
      pktsocket->config.receive_data(pktsocket, &sock, buf, result);
    }
    else if (result < 0 && (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
      OONF_WARN(LOG_PACKET, "Cannot read packet from socket %s: %s (%d)",
        netaddr_socket_to_string(&netbuf, &pktsocket->local_socket), strerror(errno), errno);
    }
  }

  if (oonf_socket_is_write(entry) && abuf_getlen(&pktsocket->out) > 0) {
    /* handle outgoing data */
    pkt = abuf_getptr(&pktsocket->out);

    /* copy remote socket */
    memcpy(&sock, pkt, sizeof(sock));
    pkt += sizeof(sock);

    /* copy length */
    memcpy(&length, pkt, 2);
    pkt += 2;

    /* try to send packet */
    result = os_fd_sendto(&entry->fd, pkt, length, &sock, pktsocket->config.dont_route);
    if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      /* try again later */
      OONF_DEBUG(
        LOG_PACKET, "Sending to %s %s could block, try again later", netaddr_socket_to_string(&netbuf, &sock), interf);
      return;
    }

    if (result < 0) {
      /* display error message */
      OONF_WARN(LOG_PACKET, "Cannot send UDP packet to %s: %s (%d)", netaddr_socket_to_string(&netbuf, &sock),
        strerror(errno), errno);
    }
    else {
      OONF_DEBUG(LOG_PACKET, "Sent %" PRINTF_SSIZE_T_SPECIFIER " bytes to %s %s", result,
        netaddr_socket_to_string(&netbuf, &sock), interf);
    }
    /* remove data from outgoing buffer (both for success and for final error */
    abuf_pull(&pktsocket->out, sizeof(sock) + 2 + length);
  }

  if (abuf_getlen(&pktsocket->out) == 0) {
    /* nothing left to send, disable outgoing events */
    oonf_socket_set_write(&pktsocket->scheduler_entry, false);
  }
}

/**
 * Callbacks for events on the interface
 * @param l OS interface listener
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_interface_listener(struct os_interface_listener *l) {
  struct oonf_packet_managed *managed;
  int result;

  /* calculate managed socket for this event */
  managed = container_of(l, struct oonf_packet_managed, _if_listener);

  result = _apply_managed(managed);
  OONF_DEBUG(LOG_PACKET, "Result from interface %s triggered socket reconfiguration: %d",
             l->data->name, result);

  return result;
}
