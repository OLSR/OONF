
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

#ifndef OONF_RFC5444_H_
#define OONF_RFC5444_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/base/oonf_duplicate_set.h>
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/librfc5444/rfc5444.h>
#include <oonf/librfc5444/rfc5444_context.h>
#include <oonf/librfc5444/rfc5444_iana.h>
#include <oonf/librfc5444/rfc5444_reader.h>
#include <oonf/librfc5444/rfc5444_writer.h>

/*! subsystem identifier */
#define OONF_RFC5444_SUBSYSTEM "rfc5444"

/**
 * suggested priorities for RFC5444 readers
 */
enum
{
  RFC5444_VALIDATOR_PRIORITY = -256,
  RFC5444_MAIN_PARSER_PRIORITY = 0,
  RFC5444_LQ_PARSER_PRIORITY = 64,
  RFC5444_PLUGIN_PARSER_PRIORITY = 256,
};

/*! Configuration section for global mesh settings */
#define CFG_RFC5444_SECTION "mesh"

enum
{
  /*! Maximum buffer size for address TLVs before splitting */
  RFC5444_ADDRTLV_BUFFER = 65536,
};

/*! Interface name for unicast targets */
#define RFC5444_UNICAST_INTERFACE OS_INTERFACE_ANY

/*! memory class for rfc5444 protocol */
#define RFC5444_CLASS_PROTOCOL "RFC5444 protocol"

/*! memory class for rfc5444 interface */
#define RFC5444_CLASS_INTERFACE "RFC5444 interface"

/*! memory class for rfc5444 target */
#define RFC5444_CLASS_TARGET "RFC5444 target"

struct oonf_rfc5444_target;

/**
 * Parameters regarding currently parsed RFC5444 packet
 */
struct oonf_rfc5444_input_parameters {
  /*! source address of currently parsed RFC5444 packet */
  struct netaddr *src_address;

  /*! source address and port of currently parsed RFC5444 packet */
  union netaddr_socket *src_socket;

  /*! interface of currently parsed RFC5444 packet */
  struct oonf_rfc5444_interface *interface;

  /*! true if currently parsed RFC5444 packet was multicast */
  bool is_multicast;
};
/**
 * Representation of a rfc5444 based protocol
 */
struct oonf_rfc5444_protocol {
  /*! name of the protocol */
  char name[32];

  /*! port number of the protocol */
  uint16_t port;

  /**
   * true if the local port must be the protocol port,
   * false if it may be random
   */
  bool fixed_local_port;

  /*! IP protocol number for raw IP communication */
  int ip_proto;

  /*! parameters of currently parsed incoming packet */
  struct oonf_rfc5444_input_parameters input;

  /*! RFC5444 reader for this protocol instance */
  struct rfc5444_reader reader;

  /*! RFC5444 writer for this protocol instance */
  struct rfc5444_writer writer;

  /*! processed set as defined in OLSRv2 */
  struct oonf_duplicate_set processed_set;

  /*! forwarded set as defined in OLSRv2 */
  struct oonf_duplicate_set forwarded_set;

  /*! node for tree of protocols */
  struct avl_node _node;

  /*! tree of interfaces for this protocol */
  struct avl_tree _interface_tree;

  /*! reference count of this protocol */
  int _refcount;

  /*! number of users who need a packet sequence number for all packets */
  int _pktseqno_refcount;

  /*! next protocol message sequence number */
  uint16_t _msg_seqno;

  /*! message buffer for protocol */
  uint8_t _msg_buffer[RFC5444_MAX_MESSAGE_SIZE];

  /*! buffer for addresstlvs before splitting the message */
  uint8_t _addrtlv_buffer[RFC5444_ADDRTLV_BUFFER];
};

/**
 * Representation of a rfc5444 interface of a protocol
 */
struct oonf_rfc5444_interface {
  /*! name of interface */
  char name[IF_NAMESIZE];

  /*! backpointer to protocol */
  struct oonf_rfc5444_protocol *protocol;

  /*! Node for tree of interfaces in protocol */
  struct avl_node _node;

  /*! tree of unicast targets */
  struct avl_tree _target_tree;

  /*! tree of interface event listeners of this interface */
  struct list_entity _listener;

  /*! managed socket for this interface */
  struct oonf_packet_managed _socket;

  /*! current socket configuration of this interface */
  struct oonf_packet_managed_config _socket_config;

  /*! pointer to ipv4 multicast targets for this interface */
  struct oonf_rfc5444_target *multicast4;

  /*! pointer to ipv6 multicast targets for this interface */
  struct oonf_rfc5444_target *multicast6;

  /*! interval the multiplexer will wait until it generates a packet */
  uint64_t aggregation_interval;

  /*!
   * value to overwrite configured aggregation interval,
   * 0 to use configured value
   */
  uint64_t overwrite_aggregation_interval;

  /*! number of users of this interface */
  int _refcount;
};

/**
 * Represents a listener to the interface events of a rfc5444 interface
 */
struct oonf_rfc5444_interface_listener {
  /**
   * Callback to signal a change of the RFC5444 interface
   * @param l this interface listener
   * @param changed true if a socket had to be reconfigured
   */
  void (*cb_interface_changed)(struct oonf_rfc5444_interface_listener *l, bool changed);

  /*! backpointer to rfc5444 interface */
  struct oonf_rfc5444_interface *interface;

  /*! node for list of listeners of an interface */
  struct list_entity _node;
};

/**
 * Represents a target (destination IP) of a rfc5444 interface
 */
struct oonf_rfc5444_target {
  /*! rfc5444 API representation of the target */
  struct rfc5444_writer_target rfc5444_target;

  /*! destination IP */
  struct netaddr dst;

  /*! backpointer to interface */
  struct oonf_rfc5444_interface *interface;

  /*! node for tree of targets for unicast interfaces */
  struct avl_node _node;

  /*! timer for message aggregation on interface */
  struct oonf_timer_instance _aggregation;

  /*! number of users of this target */
  int _refcount;

  /*! number of users requesting a packet sequence number for this target */
  int _pktseqno_refcount;

  /*! last packet sequence number used for this target */
  uint16_t _pktseqno;

  /*! packet output buffer for target */
  uint8_t _packet_buffer[RFC5444_MAX_PACKET_SIZE];
};

EXPORT struct oonf_rfc5444_protocol *oonf_rfc5444_add_protocol(const char *name, bool fixed_local_port);
EXPORT void oonf_rfc5444_remove_protocol(struct oonf_rfc5444_protocol *);
EXPORT void oonf_rfc5444_reconfigure_protocol(struct oonf_rfc5444_protocol *, uint16_t port, int ip_proto);
EXPORT struct oonf_rfc5444_protocol *oonf_rfc5444_get_default_protocol(void);

EXPORT struct oonf_rfc5444_interface *oonf_rfc5444_add_interface(
  struct oonf_rfc5444_protocol *protocol, struct oonf_rfc5444_interface_listener *, const char *name);
EXPORT void oonf_rfc5444_remove_interface(struct oonf_rfc5444_interface *, struct oonf_rfc5444_interface_listener *);
EXPORT void oonf_rfc5444_reconfigure_interface(
  struct oonf_rfc5444_interface *interf, struct oonf_packet_managed_config *config);
EXPORT struct oonf_rfc5444_target *oonf_rfc5444_add_target(
  struct oonf_rfc5444_interface *interface, struct netaddr *dst);
EXPORT void oonf_rfc5444_remove_target(struct oonf_rfc5444_target *target);
EXPORT void oonf_rfc5444_send_target_data(struct oonf_rfc5444_target *target, const void *ptr, size_t len);
EXPORT void oonf_rfc5444_send_interface_data(
  struct oonf_rfc5444_interface *interf, const struct netaddr *dst, const void *ptr, size_t len);

EXPORT uint64_t oonf_rfc5444_interface_set_aggregation(struct oonf_rfc5444_interface *interf, uint64_t aggregation);

EXPORT const union netaddr_socket *oonf_rfc5444_interface_get_local_socket(
  struct oonf_rfc5444_interface *rfc5444_if, int af_type);
EXPORT const union netaddr_socket *oonf_rfc5444_target_get_local_socket(struct oonf_rfc5444_target *target);

EXPORT enum rfc5444_result oonf_rfc5444_send_if(struct oonf_rfc5444_target *, uint8_t msgid);
EXPORT enum rfc5444_result oonf_rfc5444_send_all(
  struct oonf_rfc5444_protocol *protocol, uint8_t msgid, uint8_t addr_len, rfc5444_writer_targetselector useIf);

EXPORT void oonf_rfc5444_block_output(bool block);

/**
 * @param protocol RFC5444 protocol
 * @param name interface name
 * @return RFC5444 interface, NULL if not found
 */
static INLINE struct oonf_rfc5444_interface *
oonf_rfc5444_get_interface(struct oonf_rfc5444_protocol *protocol, const char *name) {
  struct oonf_rfc5444_interface *interf;
  return avl_find_element(&protocol->_interface_tree, name, interf, _node);
}

/**
 * Flush a target and send out the message/packet immediately
 * @param target rfc5444 target
 * @param force true to force an empty packet if necessary, false will only
 *   flush if a message is in the buffer
 */
static INLINE void
oonf_rfc5444_flush_target(struct oonf_rfc5444_target *target, bool force) {
  rfc5444_writer_flush(&target->interface->protocol->writer, &target->rfc5444_target, force);
}

/**
 * @param writer pointer to rfc5444 writer
 * @return pointer to rfc5444 target used by message
 */
static INLINE struct oonf_rfc5444_target *
oonf_rfc5444_get_target_from_writer(struct rfc5444_writer *writer) {
  return container_of_if_notnull(writer->msg_target, struct oonf_rfc5444_target, rfc5444_target);
}

/**
 * @param target rfc5444 writer target
 * @return pointer to oonf_rfc5444 target
 */
static INLINE struct oonf_rfc5444_target *
oonf_rfc5444_get_target_from_rfc5444_target(struct rfc5444_writer_target *target) {
  return container_of(target, struct oonf_rfc5444_target, rfc5444_target);
}

/**
 * @param interf pointer to rfc5444 interface
 * @return pointer to olsr interface
 */
static INLINE struct os_interface_listener *
oonf_rfc5444_get_core_if_listener(struct oonf_rfc5444_interface *interf) {
  return &interf->_socket._if_listener;
}

/**
 * @param interface pointer to rfc5444 interface
 * @param af_type address family
 * @return true if the target (address family type) socket is active
 */
static INLINE bool
oonf_rfc5444_is_interface_active(struct oonf_rfc5444_interface *interface, int af_type) {
  return oonf_packet_managed_is_active(&interface->_socket, af_type);
}

/**
 * @param target pointer to rfc5444 target
 * @return true if the target (address family type) socket is active
 */
static INLINE bool
oonf_rfc5444_is_target_active(struct oonf_rfc5444_target *target) {
  return target != NULL &&
         oonf_packet_managed_is_active(&target->interface->_socket, netaddr_get_address_family(&target->dst));
}

/**
 * @param pointer to rfc5444 interface
 * @returns true if interface is in routing mode, false otherwise
 */
static INLINE bool
oonf_rfc5444_is_interface_routing(struct oonf_rfc5444_interface *interface) {
  return !interface->_socket.config.dont_route;
}

/**
 * Sets the routing mode of a rfc5444 interface
 * @param pointer to rfc5444 interface
 * @param route true to acticate routing mode, false to deactivate it
 */
static INLINE void
oonf_rfc5444_set_interface_routing(struct oonf_rfc5444_interface *interface, bool route) {
  if (oonf_rfc5444_is_interface_routing(interface) != route) {
    interface->_socket.config.dont_route = !route;
    oonf_rfc5444_reconfigure_interface(interface, NULL);
  }
}
/**
 * Request a protocol wide packet sequence number
 * @param protocol pointer to rfc5444 protocol instance
 */
static INLINE void
oonf_rfc5444_add_protocol_pktseqno(struct oonf_rfc5444_protocol *protocol) {
  protocol->_pktseqno_refcount++;
}

/**
 * Release the request for a protocol wide packet sequence number
 * @param protocol pointer to rfc5444 protocol instance
 */
static INLINE void
oonf_rfc5444_remove_protocol_pktseqno(struct oonf_rfc5444_protocol *protocol) {
  if (protocol->_pktseqno_refcount > 0) {
    protocol->_pktseqno_refcount--;
  }
}

/**
 * Request packet sequence number for a target
 * @param target rfc5444 target
 */
static INLINE void
oonf_rfc5444_add_target_pktseqno(struct oonf_rfc5444_target *target) {
  target->_pktseqno_refcount++;
}

/**
 * Release the request for a packet sequence number for a target
 * @param target rfc5444 target
 */
static INLINE void
oonf_rfc5444_remove_target_pktseqno(struct oonf_rfc5444_target *target) {
  if (target->_pktseqno_refcount > 0) {
    target->_pktseqno_refcount--;
  }
}

/**
 * @param target pointer to rfc5444 target instance
 * @return last used packet sequence number on this target
 */
static INLINE uint16_t
oonf_rfc5444_get_last_packet_seqno(struct oonf_rfc5444_target *target) {
  return target->_pktseqno;
}

/**
 * Generates a new message sequence number for a protocol.
 * @param protocol pointer to rfc5444 protocol instance
 * @return new message sequence number
 */
static INLINE uint16_t
oonf_rfc5444_get_next_message_seqno(struct oonf_rfc5444_protocol *protocol) {
  protocol->_msg_seqno++;

  return protocol->_msg_seqno;
}

#endif /* OONF_RFC5444_H_ */
