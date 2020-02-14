
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

#ifndef OONF_PACKET_SOCKET_H_
#define OONF_PACKET_SOCKET_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/base/oonf_callback.h>
#include <oonf/base/oonf_socket.h>
#include <oonf/base/os_interface.h>

#ifndef _WIN32
#include <net/if.h>
#endif

/*! subsystem identifier */
#define OONF_PACKET_SUBSYSTEM "packet_socket"

struct oonf_packet_socket;

enum
{
  OONF_PACKET_ERRNO1_SUPPRESSION_THRESHOLD = 10,
  OONF_PACKET_ERRNO1_SUPPRESSION_INTERVAL = 60000,
};

/**
 * Configuraten of a packet socket
 */
struct oonf_packet_config {
  /*! pointer to buffer for incoming data */
  void *input_buffer;

  /*! length of input buffer */
  size_t input_buffer_length;

  /**
   * Callback triggered when an UDP packet has been received
   * @param psock packet socket
   * @param from IP source address
   * @param ptr pointer to packet data
   * @param length length of packet data
   */
  void (*receive_data)(struct oonf_packet_socket *psock, union netaddr_socket *from, void *ptr, size_t length);

  /*! true if the outgoing UDP traffic should not be routed */
  bool dont_route;

  /*! user defined pointer */
  void *user;
};

/**
 * Definition of a packet socket
 */
struct oonf_packet_socket {
  /*! hook into global list of packet sockets */
  struct list_entity node;

  /*! scheduler hook to handle incoming and outgoing data */
  struct oonf_socket_entry scheduler_entry;

  /*! address and port of the local UDP socket */
  union netaddr_socket local_socket;

  /*! IP protocol number for raw sockets */
  int protocol;

  /*! outgoing buffer */
  struct autobuf out;

  /*! interface data the socket is bound to */
  struct os_interface *os_if;

  /*! configuration of packet socket */
  struct oonf_packet_config config;

  /*! name of socket */
  char socket_name[sizeof(struct netaddr_str) + 5];

  /*! true if errno==1 suppression is active */
  bool _errno1_suppression;

  /*! begin of current errno==1 measurement interval */
  uint64_t _errno1_measurement_time;

  /*! number of suppressed errno==1 warnings */
  uint32_t _errno1_count;
};

/**
 * Configuration of a managed dualstack unicast
 * (and optionally multicast) UDP socket
 */
struct oonf_packet_managed_config {
  /*! access control list for incoming source IP addresses */
  struct netaddr_acl acl;

  /*! name to bind to socket on */
  char interface[IF_NAMESIZE];

  /*! access control list to restrict the IPs the socket is bound to */
  struct netaddr_acl bindto;

  /*! IPv4 multicast address for socket */
  struct netaddr multicast_v4;

  /*! IPv6 multicast address for socket */
  struct netaddr multicast_v6;

  /*! unicast UDP port for socket, 0 for random port */
  int32_t port;

  /*! multicast UDP port for socket, 0 for same as unicast port */
  int32_t multicast_port;

  /*! IP protocol id for socket, used for raw sockets */
  int32_t protocol;

  /*! true if multicast should be looped locally */
  bool loop_multicast;

  /*! TTL of outgoing multicast traffic */
  int32_t ttl_multicast;

  /*! true if socket needs interface to switch to mesh mode */
  bool mesh;

  /*! true if this is a raw IP socket */
  bool rawip;

  /*! IP dscp value for outgoing traffic */
  int32_t dscp;
};

/**
 * managed dualstack UDP socket
 */
struct oonf_packet_managed {
  /**
   * socket for send/receive IPv4 UDP unicast
   * and sending IPv4 UDP multicast
   */
  struct oonf_packet_socket socket_v4;

  /*! socket for receiving IPv4 UDP multicast */
  struct oonf_packet_socket multicast_v4;

  /**
   * socket for send/receive IPv6 UDP unicast
   * and sending IPv6 UDP multicast
   */
  struct oonf_packet_socket socket_v6;

  /*! socket for receiving IPv4 UDP multicast */
  struct oonf_packet_socket multicast_v6;

  /*! socket configuration that will be used for all four sockets */
  struct oonf_packet_config config;

  /**
   * Callback to inform about a change of socket settings
   * @param managed managed socket
   * @param changed true if one of the sockets had to be reconfigured
   */
  void (*cb_settings_change)(struct oonf_packet_managed *managed, bool changed);

  /*! helper for delayed change callback handling */
  struct oonf_callback _change_callback;

  /*! parameter for delayed change callback */
  bool _change_callback_flag;

  /*! configuration of managed socket */
  struct oonf_packet_managed_config _managed_config;

  /*! interface listener to detect changes */
  struct os_interface_listener _if_listener;
};

EXPORT int oonf_packet_add(struct oonf_packet_socket *, union netaddr_socket *local, struct os_interface *);
EXPORT int oonf_packet_raw_add(
  struct oonf_packet_socket *, int protocol, union netaddr_socket *local, struct os_interface *os_if);
EXPORT void oonf_packet_remove(struct oonf_packet_socket *, bool);

EXPORT int oonf_packet_send(struct oonf_packet_socket *, union netaddr_socket *remote, const void *data, size_t length);
EXPORT int oonf_packet_send_managed(
  struct oonf_packet_managed *, union netaddr_socket *remote, const void *data, size_t length);
EXPORT int oonf_packet_send_managed_multicast(
  struct oonf_packet_managed *managed, const void *data, size_t length, int af_type);
EXPORT void oonf_packet_add_managed(struct oonf_packet_managed *);
EXPORT int oonf_packet_apply_managed(struct oonf_packet_managed *, const struct oonf_packet_managed_config *);
EXPORT void oonf_packet_remove_managed(struct oonf_packet_managed *, bool force);
EXPORT bool oonf_packet_managed_is_active(struct oonf_packet_managed *managed, int af_type);
EXPORT void oonf_packet_copy_managed_config(
  struct oonf_packet_managed_config *dst, const struct oonf_packet_managed_config *src);
EXPORT void oonf_packet_free_managed_config(struct oonf_packet_managed_config *config);

/**
 * @param sock pointer to packet socket
 * @return true if the socket is active to send data, false otherwise
 */
static INLINE bool
oonf_packet_is_active(struct oonf_packet_socket *sock) {
  return list_is_node_added(&sock->node);
}

#endif /* OONF_PACKET_SOCKET_H_ */
