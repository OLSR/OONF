
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

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libconfig/cfg_db.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/libcore/os_core.h>
#include <oonf/librfc5444/rfc5444_iana.h>
#include <oonf/librfc5444/rfc5444_print.h>
#include <oonf/librfc5444/rfc5444_reader.h>
#include <oonf/librfc5444/rfc5444_writer.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_duplicate_set.h>
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/base/oonf_rfc5444.h>

/* constants and definitions */
#define LOG_RFC5444 _oonf_rfc5444_subsystem.logging

/**
 * RFC5444 configuration
 */
struct _rfc5444_config {
  /*! port number to be used for RFC5444 communication */
  int32_t port;

  /*! IP protocol number to be used for RFC5444 communication */
  int ip_proto;
};

/**
 * RFC5444 interface specific configuration
 */
struct _rfc5444_if_config {
  /*! packet socket configuration */
  struct oonf_packet_managed_config sock;

  /*! maximum aggregation interval for this interface */
  uint64_t aggregation_interval;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static struct oonf_rfc5444_target *_create_target(struct oonf_rfc5444_interface *, struct netaddr *dst, bool unicast);
static void _destroy_target(struct oonf_rfc5444_target *);
static void _print_packet_to_buffer(enum oonf_log_source source, union netaddr_socket *sock,
  struct oonf_rfc5444_interface *interf, const uint8_t *ptr, size_t len, const char *success, const char *error);

void _reconfigure_interface(struct oonf_rfc5444_interface *interf,
    struct oonf_packet_managed_config *config, bool ifchange_context);
static void _cb_receive_data(struct oonf_packet_socket *, union netaddr_socket *from, void *ptr, size_t length);
static void _cb_send_unicast_packet(struct rfc5444_writer *, struct rfc5444_writer_target *, void *, size_t);
static void _cb_send_multicast_packet(struct rfc5444_writer *, struct rfc5444_writer_target *, void *, size_t);
static void _cb_forward_message(struct rfc5444_reader_tlvblock_context *context, const uint8_t *buffer, size_t length);
static void _cb_msggen_notifier(struct rfc5444_writer_target *);

static bool _cb_single_target_selector(struct rfc5444_writer *, struct rfc5444_writer_target *, void *);
static bool _cb_filtered_targets_selector(
  struct rfc5444_writer *writer, struct rfc5444_writer_target *rfc5444_target, void *ptr);

static struct rfc5444_reader_addrblock_entry *_alloc_addrblock_entry(void);
static struct rfc5444_reader_tlvblock_entry *_alloc_tlvblock_entry(void);
static struct rfc5444_writer_address *_alloc_address_entry(void);
static struct rfc5444_writer_addrtlv *_alloc_addrtlv_entry(void);
static void _free_addrblock_entry(struct rfc5444_reader_addrblock_entry *addrblock);
static void _free_tlvblock_entry(struct rfc5444_reader_tlvblock_entry *tlvblock);
static void _free_address_entry(struct rfc5444_writer_address *);
static void _free_addrtlv_entry(struct rfc5444_writer_addrtlv *);

static void _cb_add_seqno(struct rfc5444_writer *, struct rfc5444_writer_target *);
static void _cb_aggregation_event(struct oonf_timer_instance *);

static void _cb_cfg_rfc5444_changed(void);
static void _cb_cfg_interface_changed(void);
static void _cb_interface_changed(struct oonf_packet_managed *managed, bool);

/* memory block for rfc5444 targets plus MTU sized packet buffer */
static struct oonf_class _protocol_memcookie = {
  .name = RFC5444_CLASS_PROTOCOL,
  .size = sizeof(struct oonf_rfc5444_protocol),
};

static struct oonf_class _interface_memcookie = {
  .name = RFC5444_CLASS_INTERFACE,
  .size = sizeof(struct oonf_rfc5444_interface),
};

static struct oonf_class _target_memcookie = {
  .name = RFC5444_CLASS_TARGET,
  .size = sizeof(struct oonf_rfc5444_target),
};

static struct oonf_class _tlvblock_memcookie = {
  .name = "RFC5444 TLVblock",
  .size = sizeof(struct rfc5444_reader_tlvblock_entry),
  .min_free_count = 32,
};

static struct oonf_class _addrblock_memcookie = {
  .name = "RFC5444 Addrblock",
  .size = sizeof(struct rfc5444_reader_addrblock_entry),
  .min_free_count = 32,
};

static struct oonf_class _address_memcookie = {
  .name = "RFC5444 Address",
  .size = sizeof(struct rfc5444_writer_address),
  .min_free_count = 32,
};

static struct oonf_class _addrtlv_memcookie = {
  .name = "RFC5444 AddrTLV",
  .size = sizeof(struct rfc5444_writer_addrtlv),
  .min_free_count = 32,
};

/* timer for aggregating multiple rfc5444 messages to the same target */
static struct oonf_timer_class _aggregation_timer = {
  .name = "RFC5444 aggregation",
  .callback = _cb_aggregation_event,
};

/* configuration settings for handler */
static struct cfg_schema_entry _rfc5444_entries[] = {
  CFG_MAP_INT32_MINMAX(
    _rfc5444_config, port, "port", RFC5444_MANET_UDP_PORT_TXT, "UDP port for RFC5444 interface", 0, 1, 65535),
  CFG_MAP_INT32_MINMAX(
    _rfc5444_config, ip_proto, "ip_proto", RFC5444_MANET_IPPROTO_TXT, "IP protocol for RFC5444 interface", 0, 1, 255),
};

static struct cfg_schema_section _rfc5444_section = {
  .type = CFG_RFC5444_SECTION,
  .mode = CFG_SSMODE_UNNAMED,
  .cb_delta_handler = _cb_cfg_rfc5444_changed,
  .entries = _rfc5444_entries,
  .entry_count = ARRAYSIZE(_rfc5444_entries),
};

static struct cfg_schema_entry _interface_entries[] = {
  CFG_MAP_ACL_V46(_rfc5444_if_config, sock.acl, "acl", ACL_DEFAULT_ACCEPT, "Access control list for RFC5444 interface"),
  CFG_MAP_ACL_V46(_rfc5444_if_config, sock.bindto, "bindto",
    "-127.0.0.0/8\0"
    "fe80::/10\0"
    "-::/0\0" ACL_FIRST_ACCEPT "\0" ACL_DEFAULT_ACCEPT,
    "Bind RFC5444 socket to an address matching this filter (both IPv4 and IPv6)"),
  CFG_MAP_NETADDR_V4(_rfc5444_if_config, sock.multicast_v4, "multicast_v4", RFC5444_MANET_MULTICAST_V4_TXT,
    "ipv4 multicast address of this socket", false, true),
  CFG_MAP_NETADDR_V6(_rfc5444_if_config, sock.multicast_v6, "multicast_v6", RFC5444_MANET_MULTICAST_V6_TXT,
    "ipv6 multicast address of this socket", false, true),
  CFG_MAP_INT32_MINMAX(
    _rfc5444_if_config, sock.dscp, "dscp", "192", "DSCP field for outgoing UDP protocol traffic", 0, 0, 255),
  CFG_MAP_BOOL(
    _rfc5444_if_config, sock.rawip, "rawip", "false", "True if a raw IP socket should be used, false to use UDP"),
  CFG_MAP_INT32_MINMAX(
    _rfc5444_if_config, sock.ttl_multicast, "multicast_ttl", "1", "TTL value of outgoing multicast traffic", 0, 1, 255),
  CFG_MAP_CLOCK(_rfc5444_if_config, aggregation_interval, "aggregation_interval", "0.100",
    "Interval in seconds for message aggregation"),

};

static struct cfg_schema_section _interface_section = {
  CFG_OSIF_SCHEMA_INTERFACE_SECTION_INIT,

  .cb_delta_handler = _cb_cfg_interface_changed,
  .entries = _interface_entries,
  .entry_count = ARRAYSIZE(_interface_entries),
  .next_section = &_rfc5444_section,
};

/* rfc5444 handling */
static const struct rfc5444_reader _reader_template = {
  .forward_message = _cb_forward_message,
  .malloc_addrblock_entry = _alloc_addrblock_entry,
  .malloc_tlvblock_entry = _alloc_tlvblock_entry,
  .free_addrblock_entry = _free_addrblock_entry,
  .free_tlvblock_entry = _free_tlvblock_entry,
};
static const struct rfc5444_writer _writer_template = {
  .malloc_address_entry = _alloc_address_entry,
  .malloc_addrtlv_entry = _alloc_addrtlv_entry,
  .free_address_entry = _free_address_entry,
  .free_addrtlv_entry = _free_addrtlv_entry,
  .msg_size = RFC5444_MAX_MESSAGE_SIZE,
  .addrtlv_size = RFC5444_ADDRTLV_BUFFER,
};

/* rfc5444_printer */
static struct autobuf _printer_buffer;
static struct rfc5444_print_session _printer_session;

static struct rfc5444_reader _printer = {
  .malloc_addrblock_entry = _alloc_addrblock_entry,
  .malloc_tlvblock_entry = _alloc_tlvblock_entry,
  .free_addrblock_entry = _free_addrblock_entry,
  .free_tlvblock_entry = _free_tlvblock_entry,
};

/* configuration for RFC5444 socket */
static uint8_t _incoming_buffer[RFC5444_MAX_PACKET_SIZE];

static struct oonf_packet_config _socket_config = {
  .input_buffer = _incoming_buffer,
  .input_buffer_length = sizeof(_incoming_buffer),
  .receive_data = _cb_receive_data,
};

/* tree of active rfc5444 protocols */
static struct avl_tree _protocol_tree;

/* default protocol */
static struct oonf_rfc5444_protocol *_rfc5444_protocol = NULL;
static struct oonf_rfc5444_interface *_rfc5444_unicast = NULL;

static const struct const_strarray _unicast_bindto_acl_value = STRARRAY_INIT("0.0.0.0\0::");

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_DUPSET_SUBSYSTEM,
  OONF_PACKET_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_rfc5444_subsystem = {
  .name = OONF_RFC5444_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .cfg_section = &_interface_section,
};
DECLARE_OONF_PLUGIN(_oonf_rfc5444_subsystem);

/* static blocking of RFC5444 output */
static bool _block_output = false;

/* additional logging targets */
static enum oonf_log_source LOG_RFC5444_R, LOG_RFC5444_W;

/**
 * Initialize RFC5444 handling system
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  avl_init(&_protocol_tree, avl_comp_strcasecmp, false);

  oonf_class_add(&_protocol_memcookie);
  oonf_class_add(&_target_memcookie);
  oonf_class_add(&_addrblock_memcookie);
  oonf_class_add(&_tlvblock_memcookie);
  oonf_class_add(&_address_memcookie);
  oonf_class_add(&_addrtlv_memcookie);

  oonf_timer_add(&_aggregation_timer);

  _rfc5444_protocol = oonf_rfc5444_add_protocol("rfc5444_iana", true);
  if (_rfc5444_protocol == NULL) {
    _cleanup();
    return -1;
  }

  oonf_class_add(&_interface_memcookie);
  _rfc5444_unicast = oonf_rfc5444_add_interface(_rfc5444_protocol, NULL, RFC5444_UNICAST_INTERFACE);
  if (_rfc5444_unicast == NULL) {
    _cleanup();
    return -1;
  }

  if (abuf_init(&_printer_buffer)) {
    _cleanup();
    return -1;
  }

  memset(&_printer_session, 0, sizeof(_printer_session));
  _printer_session.output = &_printer_buffer;

  rfc5444_reader_init(&_printer);
  rfc5444_print_add(&_printer_session, &_printer);

  LOG_RFC5444_R = oonf_log_register_source(OONF_RFC5444_SUBSYSTEM "_r");
  LOG_RFC5444_W = oonf_log_register_source(OONF_RFC5444_SUBSYSTEM "_w");
  return 0;
}

/**
 * Cleanup all allocated resources of RFC5444 handling
 */
void
_cleanup(void) {
  struct oonf_rfc5444_protocol *protocol, *p_it;
  struct oonf_rfc5444_interface *interf, *i_it;
  struct oonf_rfc5444_target *target, *t_it;

  /* cleanup existing instances */
  avl_for_each_element_safe(&_protocol_tree, protocol, _node, p_it) {
    avl_for_each_element_safe(&protocol->_interface_tree, interf, _node, i_it) {
      avl_for_each_element_safe(&interf->_target_tree, target, _node, t_it) {
        /* always remove target but never remove interface */
        target->_refcount = 1;
        interf->_refcount = 2;
        oonf_rfc5444_remove_target(target);
      }
      /* always remove interface but never remove protocol */
      interf->_refcount = 1;
      protocol->_refcount = 2;
      oonf_rfc5444_remove_interface(interf, NULL);
    }
    /* always remove protocol */
    protocol->_refcount = 1;
    oonf_rfc5444_remove_protocol(protocol);
  }

  oonf_timer_remove(&_aggregation_timer);

  if (_printer_session.output) {
    rfc5444_print_remove(&_printer_session);
    rfc5444_reader_cleanup(&_printer);
  }
  abuf_free(&_printer_buffer);

  oonf_class_remove(&_protocol_memcookie);
  oonf_class_remove(&_interface_memcookie);
  oonf_class_remove(&_target_memcookie);
  oonf_class_remove(&_tlvblock_memcookie);
  oonf_class_remove(&_addrblock_memcookie);
  oonf_class_remove(&_address_memcookie);
  oonf_class_remove(&_addrtlv_memcookie);
  return;
}

/**
 * Trigger the creation of a RFC5444 message for a specific interface
 * @param target interface for outgoing message
 * @param msgid id of created message
 * @return return code of rfc5444 writer
 */
enum rfc5444_result
oonf_rfc5444_send_if(struct oonf_rfc5444_target *target, uint8_t msgid)
{
  uint8_t addr_len;

#ifdef OONF_LOG_INFO
  struct netaddr_str buf;
#endif

  /* check if socket can send data */
  if (!oonf_rfc5444_is_target_active(target)) {
    return RFC5444_OKAY;
  }

  /* create message */
  OONF_INFO(LOG_RFC5444, "Create message id %d for protocol %s/target %s on interface %s", msgid,
    target->interface->protocol->name, netaddr_to_string(&buf, &target->dst), target->interface->name);

  addr_len = netaddr_get_address_family(&target->dst) == AF_INET ? 4 : 16;
  return rfc5444_writer_create_message(
    &target->interface->protocol->writer, msgid, addr_len, _cb_single_target_selector, target);
}

/**
 * Trigger the creation of a RFC5444 message for a group of interfaces
 * @param protocol protocol for outgoing message
 * @param msgid id of created message
 * @param addr_len length of address for this message
 * @param useIf callback to selector for interfaces
 * @return return code of rfc5444 writer
 */
enum rfc5444_result
oonf_rfc5444_send_all(
  struct oonf_rfc5444_protocol *protocol, uint8_t msgid, uint8_t addr_len, rfc5444_writer_targetselector useIf)
{
  /* create message */
  OONF_INFO(LOG_RFC5444, "Create message id %d", msgid);

  return rfc5444_writer_create_message(&protocol->writer, msgid, addr_len, _cb_filtered_targets_selector, useIf);
}

/**
 * Add a new protocol to the rfc5444 framework
 * @param name name of protocol, must be an unique identifier
 * @param fixed_local_port true if the local port must be fixed to the
 *   external port
 * @return pointer to new protocol instance, NULL if out of memory
 */
struct oonf_rfc5444_protocol *
oonf_rfc5444_add_protocol(const char *name, bool fixed_local_port) {
  struct oonf_rfc5444_protocol *protocol;

  protocol = avl_find_element(&_protocol_tree, name, protocol, _node);
  if (!protocol) {
    protocol = oonf_class_malloc(&_protocol_memcookie);
    if (protocol == NULL) {
      return NULL;
    }

    /* set name */
    strscpy(protocol->name, name, sizeof(protocol->name));
    protocol->fixed_local_port = fixed_local_port;

    /* hook into global protocol tree */
    protocol->_node.key = protocol->name;
    avl_insert(&_protocol_tree, &protocol->_node);

    /* initialize rfc5444 reader/writer */
    memcpy(&protocol->reader, &_reader_template, sizeof(_reader_template));
    memcpy(&protocol->writer, &_writer_template, sizeof(_writer_template));
    protocol->writer.msg_buffer = protocol->_msg_buffer;
    protocol->writer.addrtlv_buffer = protocol->_addrtlv_buffer;
    rfc5444_reader_init(&protocol->reader);
    rfc5444_writer_init(&protocol->writer);

    protocol->writer.message_generation_notifier = _cb_msggen_notifier;

    /* initialize processing and forwarding set */
    oonf_duplicate_set_add(&protocol->forwarded_set, OONF_DUPSET_16BIT);
    oonf_duplicate_set_add(&protocol->processed_set, OONF_DUPSET_16BIT);

    /* init interface subtree */
    avl_init(&protocol->_interface_tree, avl_comp_strcasecmp, false);
  }

  OONF_INFO(LOG_RFC5444, "Add protocol %s (refcount was %d)", name, protocol->_refcount);

  /* keep track of reference count */
  protocol->_refcount++;

  return protocol;
}

/**
 * Remove a protocol instance from the framework
 * @param protocol pointer to protocol
 */
void
oonf_rfc5444_remove_protocol(struct oonf_rfc5444_protocol *protocol) {
  struct oonf_rfc5444_interface *interf, *i_it;

  OONF_INFO(LOG_RFC5444, "Remove protocol %s (refcount was %d)", protocol->name, protocol->_refcount);

  if (protocol->_refcount > 1) {
    /* There are still users left for this protocol */
    protocol->_refcount--;
    return;
  }

  /* free all remaining interfaces */
  avl_for_each_element_safe(&protocol->_interface_tree, interf, _node, i_it) {
    oonf_rfc5444_remove_interface(interf, NULL);
  }

  /* free processing/forwarding set */
  oonf_duplicate_set_remove(&protocol->forwarded_set);
  oonf_duplicate_set_remove(&protocol->processed_set);

  /* free reader, writer and protocol itself */
  rfc5444_reader_cleanup(&protocol->reader);
  rfc5444_writer_cleanup(&protocol->writer);

  avl_remove(&_protocol_tree, &protocol->_node);
  oonf_class_free(&_protocol_memcookie, protocol);
}

/**
 * Set the port of a protocol
 * @param protocol pointer to protocol instance
 * @param port port number in host byteorder
 * @param ip_proto ip protocol number in host byteorder
 */
void
oonf_rfc5444_reconfigure_protocol(struct oonf_rfc5444_protocol *protocol, uint16_t port, int ip_proto) {
  struct oonf_rfc5444_interface *interf;

  /* nothing to do? */
  if (port == protocol->port && ip_proto == protocol->ip_proto) {
    return;
  }

  OONF_INFO(LOG_RFC5444, "Reconfigure protocol %s to port %u and ip-protocol %d", protocol->name, port, ip_proto);

  /* store protocol port */
  protocol->port = port;
  protocol->ip_proto = ip_proto;

  avl_for_each_element(&protocol->_interface_tree, interf, _node) {
    oonf_packet_remove_managed(&interf->_socket, true);
    oonf_packet_add_managed(&interf->_socket);

    if (port) {
      oonf_rfc5444_reconfigure_interface(interf, NULL);
    }
  }
}

/**
 * @return default IANA RFC5444 protocol instance
 */
struct oonf_rfc5444_protocol *
oonf_rfc5444_get_default_protocol(void) {
  return _rfc5444_protocol;
}

/**
 * Add a new interface to a rfc5444 protocol.
 * @param protocol pointer to protocol instance
 * @param listener pointer to interface listener, NULL if none
 * @param name name of interface
 * @return pointer to rfc5444 interface instance, NULL if out of memory
 */
struct oonf_rfc5444_interface *
oonf_rfc5444_add_interface(
  struct oonf_rfc5444_protocol *protocol, struct oonf_rfc5444_interface_listener *listener, const char *name) {
  struct oonf_rfc5444_interface *interf;
  uint16_t rnd;

  interf = oonf_rfc5444_get_interface(protocol, name);
  if (interf == NULL) {
    if (os_core_get_random(&rnd, sizeof(rnd))) {
      OONF_WARN(LOG_RFC5444, "Could not get random data");
      return NULL;
    }

    interf = oonf_class_malloc(&_interface_memcookie);
    if (interf == NULL) {
      return NULL;
    }

    /* set name */
    strscpy(interf->name, name, sizeof(interf->name));

    /* set protocol reference */
    interf->protocol = protocol;

    /* hook into protocol */
    interf->_node.key = interf->name;
    avl_insert(&protocol->_interface_tree, &interf->_node);

    /* initialize target subtree */
    avl_init(&interf->_target_tree, avl_comp_netaddr, false);

    /* initialize socket config */
    memcpy(&interf->_socket.config, &_socket_config, sizeof(_socket_config));
    interf->_socket.config.user = interf;
    interf->_socket.cb_settings_change = _cb_interface_changed;

    /* prevent routing of RFC5444 packets */
    interf->_socket.config.dont_route = true;

    /* initialize socket */
    oonf_packet_add_managed(&interf->_socket);

    /* initialize message sequence number */
    protocol->_msg_seqno = rnd;

    /* initialize listener list */
    list_init_head(&interf->_listener);

    /* increase protocol refcount */
    protocol->_refcount++;
  }

  OONF_INFO(LOG_RFC5444, "Add interface %s to protocol %s (refcount was %d)", name, protocol->name, interf->_refcount);

  /* increase reference count */
  interf->_refcount += 1;

  if (listener) {
    /* hookup listener */
    list_add_tail(&interf->_listener, &listener->_node);
    listener->interface = interf;
  }
  return interf;
}

/**
 * Remove a rfc5444 interface instance
 * @param interf pointer to interface instance
 * @param listener pointer to interface listener, NULL if none
 */
void
oonf_rfc5444_remove_interface(struct oonf_rfc5444_interface *interf, struct oonf_rfc5444_interface_listener *listener) {
  struct oonf_rfc5444_target *target, *t_it;

  OONF_INFO(LOG_RFC5444, "Remove interface %s from protocol %s (refcount was %d)", interf->name, interf->protocol->name,
    interf->_refcount);

  if (interf->_refcount > 1) {
    /* still users left for this interface */
    interf->_refcount--;
    return;
  }

  if (listener != NULL && listener->interface != NULL) {
    list_remove(&listener->_node);
    listener->interface = NULL;
  }

  /* remove all remaining targets */
  avl_for_each_element_safe(&interf->_target_tree, target, _node, t_it) {
    _destroy_target(target);
  }

  /* remove multicast targets */
  if (interf->multicast4) {
    _destroy_target(interf->multicast4);
  }
  if (interf->multicast6) {
    _destroy_target(interf->multicast6);
  }

  /* remove from protocol tree */
  avl_remove(&interf->protocol->_interface_tree, &interf->_node);

  /* decrease protocol refcount */
  oonf_rfc5444_remove_protocol(interf->protocol);

  /* remove socket */
  oonf_packet_remove_managed(&interf->_socket, false);

  /* cleanup configuration copy */
  oonf_packet_free_managed_config(&interf->_socket_config);

  /* free memory */
  oonf_class_free(&_interface_memcookie, interf);
}

/**
 * Reconfigure the parameters of an rfc5444 interface. You cannot reconfigure
 * the interface name with this command.
 * @param interf pointer to existing rfc5444 interface
 * @param config new socket configuration, NULL to just reapply the current
 *  configuration
 */
void
oonf_rfc5444_reconfigure_interface(struct oonf_rfc5444_interface *interf, struct oonf_packet_managed_config *config) {
  _reconfigure_interface(interf, config, false);
}

/**
 * Reconfigure the parameters of an rfc5444 interface. You cannot reconfigure
 * the interface name with this command.
 * @param interf pointer to existing rfc5444 interface
 * @param config new socket configuration, NULL to just reapply the current
 *  configuration
 */
void
_reconfigure_interface(struct oonf_rfc5444_interface *interf, struct oonf_packet_managed_config *config, bool ifchange_context) {
  struct oonf_rfc5444_target *target, *old;
  uint16_t port;
  struct netaddr_str buf;

  if (config != NULL) {
    /* copy socket configuration */
    oonf_packet_copy_managed_config(&interf->_socket_config, config);

    /* overwrite interface name */
    strscpy(interf->_socket_config.interface, interf->name, sizeof(interf->_socket_config.interface));
  }
  else {
    config = &interf->_socket_config;
  }

  /* always mesh socket */
  interf->_socket_config.mesh = true;

  /* get port */
  port = interf->protocol->port;

  /* set fixed configuration options */
  if (interf->_socket_config.rawip) {
    interf->_socket_config.port = 0;
    interf->_socket_config.multicast_port = 0;
    interf->_socket_config.protocol = interf->protocol->ip_proto;
  }
  else {
    if (interf->_socket_config.multicast_port == 0) {
      interf->_socket_config.multicast_port = port;
    }
    if (interf->protocol->fixed_local_port && interf->_socket_config.port == 0) {
      interf->_socket_config.port = port;
    }
  }

  OONF_INFO(LOG_RFC5444, "Reconfigure RFC5444 interface %s to port %u/%u and protocol %d", interf->name,
    interf->_socket_config.port, interf->_socket_config.multicast_port, interf->_socket_config.protocol);

  if (strcmp(interf->name, RFC5444_UNICAST_INTERFACE) == 0) {
    /* unicast interface */
    netaddr_invalidate(&interf->_socket_config.multicast_v4);
    netaddr_invalidate(&interf->_socket_config.multicast_v6);
    interf->_socket_config.port = port;
    interf->_socket_config.interface[0] = 0;
    netaddr_acl_from_strarray(&interf->_socket_config.bindto, &_unicast_bindto_acl_value);
  }

  if (port == 0) {
    /* delay configuration apply */
    OONF_INFO(LOG_RFC5444, "    delay configuration, we still lack to protocol port");
    return;
  }

  if (!ifchange_context) {
    /* apply socket configuration */
    oonf_packet_apply_managed(&interf->_socket, &interf->_socket_config);
  }

  /* handle IPv4 multicast target */
  if (interf->multicast4) {
    old = interf->multicast4;
    interf->multicast4 = NULL;
  }
  else {
    old = NULL;
  }
  if (netaddr_get_address_family(&config->multicast_v4) != AF_UNSPEC) {
    target = _create_target(interf, &config->multicast_v4, false);
    if (target == NULL) {
      OONF_WARN(LOG_RFC5444, "Could not create multicast target %s for interface %s",
        netaddr_to_string(&buf, &config->multicast_v4), interf->name);
      interf->multicast4 = old;
      old = NULL;
    }
    else {
      interf->multicast4 = target;
    }
  }
  if (old) {
    _destroy_target(old);
  }

  /* handle IPv6 multicast target */
  if (interf->multicast6) {
    old = interf->multicast6;
    interf->multicast6 = NULL;
  }
  else {
    old = NULL;
  }
  if (netaddr_get_address_family(&config->multicast_v6) != AF_UNSPEC) {
    target = _create_target(interf, &config->multicast_v6, false);
    if (target == NULL) {
      OONF_WARN(LOG_RFC5444, "Could not create multicast socket %s for interface %s",
        netaddr_to_string(&buf, &config->multicast_v6), interf->name);
      interf->multicast6 = old;
      old = NULL;
    }
    else {
      interf->multicast6 = target;
    }
  }
  if (old) {
    _destroy_target(old);
  }
}

/**
 * Set/Reset value to overwrite the configured aggregation
 * interval of a RFC5444 interface
 * @param interf RFC5444 interface
 * @param aggregation new aggregation interval, 0 to reset to
 *   configured value
 * @return old aggregation interval, 0 if configured value was used
 */
uint64_t
oonf_rfc5444_interface_set_aggregation(struct oonf_rfc5444_interface *interf, uint64_t aggregation) {
  uint64_t old;

  old = interf->overwrite_aggregation_interval;
  interf->overwrite_aggregation_interval = aggregation;
  return old;
}

/**
 * Add an unicast target to a rfc5444 interface
 * @param interf pointer to interface instance
 * @param dst pointer to destination IP address
 * @return pointer to target, NULL if out of memory
 */
struct oonf_rfc5444_target *
oonf_rfc5444_add_target(struct oonf_rfc5444_interface *interf, struct netaddr *dst) {
  struct oonf_rfc5444_target *target;
#ifdef OONF_LOG_INFO
  struct netaddr_str nbuf;
#endif

  target = avl_find_element(&interf->_target_tree, dst, target, _node);
  if (!target) {
    target = _create_target(interf, dst, true);
    if (target == NULL) {
      return NULL;
    }

    /* hook into interface tree */
    target->_node.key = &target->dst;
    avl_insert(&interf->_target_tree, &target->_node);
  }

  OONF_INFO(LOG_RFC5444, "Add target %s to interface %s on protocol %s (refcount was %d)",
    netaddr_to_string(&nbuf, dst), interf->name, interf->protocol->name, target->_refcount);

  /* increase interface refcount */
  interf->_refcount++;
  return target;
}

/**
 * Removes an unicast target from a rfc5444 interface
 * @param target pointer to target instance
 */
void
oonf_rfc5444_remove_target(struct oonf_rfc5444_target *target) {
#ifdef OONF_LOG_INFO
  struct netaddr_str nbuf;
#endif

  OONF_INFO(LOG_RFC5444, "Remove target %s from interface %s on protocol %s (refcount was %d)",
    netaddr_to_string(&nbuf, &target->dst), target->interface->name, target->interface->protocol->name,
    target->_refcount);

  if (target->_refcount > 1) {
    /* target still in use */
    target->_refcount--;
    return;
  }

  /* remove from protocol tree */
  avl_remove(&target->interface->_target_tree, &target->_node);

  /* decrease protocol refcount */
  oonf_rfc5444_remove_interface(target->interface, NULL);

  /* remove target */
  _destroy_target(target);
}

/**
 * Send a raw RFC5444 packet to a target
 * @param target target for the packet data
 * @param ptr pointer to data
 * @param len length of data
 */
void
oonf_rfc5444_send_target_data(struct oonf_rfc5444_target *target, const void *ptr, size_t len) {
  union netaddr_socket sock;
  struct os_interface_listener *interf;

  interf = oonf_rfc5444_get_core_if_listener(target->interface);
  netaddr_socket_init(&sock, &target->dst, target->interface->protocol->port, interf->data->index);

  _print_packet_to_buffer(LOG_RFC5444_W, &sock, target->interface, ptr, len, "Outgoing RFC5444 packet to",
    "Error while parsing outgoing RFC5444 packet to");

  if (_block_output) {
    OONF_DEBUG(LOG_RFC5444, "Output blocked");
    return;
  }
  if (target == target->interface->multicast4 || target == target->interface->multicast6) {
    oonf_packet_send_managed_multicast(&target->interface->_socket, ptr, len, netaddr_get_address_family(&target->dst));
  }
  else {
    oonf_packet_send_managed(&target->interface->_socket, &sock, ptr, len);
  }
}

/**
 * Send a raw RFC5444 packet through an interface to a destination address
 * @param interf rfc5444 interface
 * @param dst destination address for packet
 * @param ptr pointer to data
 * @param len length of data
 */
void
oonf_rfc5444_send_interface_data(
  struct oonf_rfc5444_interface *interf, const struct netaddr *dst, const void *ptr, size_t len) {
  union netaddr_socket sock;
  struct os_interface_listener *os_interf;

  os_interf = oonf_rfc5444_get_core_if_listener(interf);
  netaddr_socket_init(&sock, dst, interf->protocol->port, os_interf->data->index);

  _print_packet_to_buffer(LOG_RFC5444_W, &sock, interf, ptr, len, "Outgoing RFC5444 packet to",
    "Error while parsing outgoing RFC5444 packet to");

  if (_block_output) {
    OONF_DEBUG(LOG_RFC5444, "Output blocked");
    return;
  }

  if (netaddr_is_in_subnet(&NETADDR_IPV4_MULTICAST, dst) || netaddr_is_in_subnet(&NETADDR_IPV6_MULTICAST, dst)) {
    oonf_packet_send_managed_multicast(&interf->_socket, ptr, len, netaddr_get_address_family(dst));
  }
  else {
    oonf_packet_send_managed(&interf->_socket, &sock, ptr, len);
  }
}

/**
 * @param target oonf rfc5444 target
 * @return local socket corresponding to target destination
 */
const union netaddr_socket *
oonf_rfc5444_target_get_local_socket(struct oonf_rfc5444_target *target) {
  int family;

  family = netaddr_get_address_family(&target->dst);
  return oonf_rfc5444_interface_get_local_socket(target->interface, family);
}

/**
 * @param rfc5444_if oonf rfc5444 interface
 * @param af_type address family type
 * @return local socket corresponding to address family
 */
const union netaddr_socket *
oonf_rfc5444_interface_get_local_socket(struct oonf_rfc5444_interface *rfc5444_if, int af_type) {
  if (af_type == AF_INET) {
    return &rfc5444_if->_socket.socket_v4.local_socket;
  }
  if (af_type == AF_INET6) {
    return &rfc5444_if->_socket.socket_v6.local_socket;
  }
  return NULL;
}

/**
 * This function can block all output of the RFC5444 code
 * @param block true to block everything, false to unblock
 */
void
oonf_rfc5444_block_output(bool block) {
  _block_output = block;
}

/**
 * Create a new rfc5444 target
 * @param interf rfc5444 interface
 * @param dst destination ip address
 * @param unicast true of unicast, false if multicast
 * @return pointer to target, NULL if out of memory
 */
static struct oonf_rfc5444_target *
_create_target(struct oonf_rfc5444_interface *interf, struct netaddr *dst, bool unicast) {
  static struct oonf_rfc5444_target *target;
  uint16_t rnd;

  if (os_core_get_random(&rnd, sizeof(rnd))) {
    OONF_WARN(LOG_RFC5444, "Could not get random data");
    return NULL;
  }

  target = oonf_class_malloc(&_target_memcookie);
  if (target == NULL) {
    return NULL;
  }

  /* initialize rfc5444 interfaces */
  target->rfc5444_target.packet_buffer = target->_packet_buffer;
  target->rfc5444_target.packet_size = RFC5444_MAX_PACKET_SIZE;
  target->rfc5444_target.addPacketHeader = _cb_add_seqno;
  if (unicast) {
    target->rfc5444_target.sendPacket = _cb_send_unicast_packet;
  }
  else {
    target->rfc5444_target.sendPacket = _cb_send_multicast_packet;
  }
  rfc5444_writer_register_target(&interf->protocol->writer, &target->rfc5444_target);

  /* copy socket description */
  memcpy(&target->dst, dst, sizeof(target->dst));

  /* set interface reference */
  target->interface = interf;

  /* aggregation timer */
  target->_aggregation.class = &_aggregation_timer;

  target->_refcount = 1;

  /* initialize pktseqno */
  target->_pktseqno = rnd;

  return target;
}

/**
 * Destroy a target and free its resources
 * @param target pointer to rfc5444 target
 */
static void
_destroy_target(struct oonf_rfc5444_target *target) {
  /* cleanup interface */
  rfc5444_writer_unregister_target(&target->interface->protocol->writer, &target->rfc5444_target);

  /* stop timer */
  oonf_timer_stop(&target->_aggregation);

  /* free memory */
  oonf_class_free(&_target_memcookie, target);
}

/**
 * Print a rfc5444 packet to the logging system
 * @param sock socket the packet is reffering to
 * @param interf pointer to rfc5444 interface
 * @param ptr pointer to packet
 * @param len length of packet
 * @param success text prefix for successful printing
 * @param error text prefix when error happens during packet parsing
 */
static void
_print_packet_to_buffer(enum oonf_log_source source, union netaddr_socket *sock __attribute__((unused)),
  struct oonf_rfc5444_interface *interf __attribute__((unused)), const uint8_t *ptr, size_t len,
  const char *success __attribute__((unused)), const char *error __attribute__((unused))) {
  enum rfc5444_result result;
  struct netaddr_str buf;

  if (oonf_log_mask_test(log_global_mask, source, LOG_SEVERITY_DEBUG)) {
    abuf_clear(&_printer_buffer);
    abuf_hexdump(&_printer_buffer, "", ptr, len);

    result = rfc5444_reader_handle_packet(&_printer, ptr, len);
    if (result) {
      OONF_WARN(source, "%s %s for printing: %s (%d)", error, netaddr_socket_to_string(&buf, sock),
        rfc5444_strerror(result), result);
      OONF_WARN(source, "packet: %s", abuf_getptr(&_printer_buffer));
    }
    else {
      OONF_DEBUG(source, "%s %s through %s:", success, netaddr_socket_to_string(&buf, sock), interf->name);
      OONF_DEBUG(source, "packet: %s", abuf_getptr(&_printer_buffer));
    }
  }
}

/**
 * Handle incoming packet from a socket
 * @param sock pointer to packet socket
 * @param from originator of incoming packet
 * @param length length of incoming packet
 */
static void
_cb_receive_data(struct oonf_packet_socket *sock, union netaddr_socket *from, void *ptr, size_t length) {
  struct oonf_rfc5444_protocol *protocol;
  struct oonf_rfc5444_interface *interf;
  enum rfc5444_result result;
  struct netaddr source_ip;
  struct netaddr_str buf;

  interf = sock->config.user;
  protocol = interf->protocol;

  if (netaddr_from_socket(&source_ip, from)) {
    OONF_WARN(LOG_RFC5444, "Could not convert socket to address: %s", netaddr_socket_to_string(&buf, from));
    return;
  }

  protocol->input.src_socket = from;
  protocol->input.src_address = &source_ip;
  protocol->input.interface = interf;

  protocol->input.is_multicast = sock == &interf->_socket.multicast_v4 || sock == &interf->_socket.multicast_v6;

  if (strcmp(interf->name, RFC5444_UNICAST_INTERFACE) == 0 &&
      (netaddr_is_in_subnet(&NETADDR_IPV4_LINKLOCAL, &source_ip) ||
        netaddr_is_in_subnet(&NETADDR_IPV6_LINKLOCAL, &source_ip))) {
    OONF_DEBUG(LOG_RFC5444, "Ignore linklocal traffic on generic unicast interface");
    return;
  }

  _print_packet_to_buffer(LOG_RFC5444_R, from, interf, ptr, length, "Incoming RFC5444 packet from",
    "Error while parsing incoming RFC5444 packet from");

  result = rfc5444_reader_handle_packet(&protocol->reader, ptr, length);
  if (result < 0) {
    OONF_WARN(LOG_RFC5444, "Error while parsing incoming packet from %s: %s (%d)", netaddr_socket_to_string(&buf, from),
      rfc5444_strerror(result), result);
    OONF_WARN_HEX(LOG_RFC5444, ptr, length, "%s", abuf_getptr(&_printer_buffer));
  }
}

/**
 * Callback for sending a multicast packet to a rfc5444 target
 * @param writer rfc5444 writer
 * @param target rfc5444 target
 * @param ptr pointer to outgoing buffer
 * @param len length of buffer
 */
static void
_cb_send_multicast_packet(
  struct rfc5444_writer *writer __attribute__((unused)), struct rfc5444_writer_target *target, void *ptr, size_t len) {
  struct oonf_rfc5444_target *t;
  struct os_interface_listener *if_listener;
  union netaddr_socket sock;

  t = container_of(target, struct oonf_rfc5444_target, rfc5444_target);

  if_listener = oonf_rfc5444_get_core_if_listener(t->interface);
  netaddr_socket_init(&sock, &t->dst, t->interface->protocol->port, if_listener->data->index);

  _print_packet_to_buffer(LOG_RFC5444_W, &sock, t->interface, ptr, len, "Outgoing RFC5444 packet to",
    "Error while parsing outgoing RFC5444 packet to");

  if (_block_output) {
    OONF_DEBUG(LOG_RFC5444, "Output blocked");
    return;
  }
  oonf_packet_send_managed_multicast(&t->interface->_socket, ptr, len, netaddr_get_address_family(&t->dst));
}

/**
 * Callback for sending an unicast packet to a rfc5444 target
 * @param writer rfc5444 writer
 * @param target rfc5444 target
 * @param ptr pointer to outgoing buffer
 * @param len length of buffer
 */
static void
_cb_send_unicast_packet(
  struct rfc5444_writer *writer __attribute__((unused)), struct rfc5444_writer_target *target, void *ptr, size_t len) {
  struct oonf_rfc5444_target *t;
  union netaddr_socket sock;
  struct os_interface_listener *interf;

  t = container_of(target, struct oonf_rfc5444_target, rfc5444_target);

  interf = oonf_rfc5444_get_core_if_listener(t->interface);
  netaddr_socket_init(&sock, &t->dst, t->interface->protocol->port, interf->data->index);

  _print_packet_to_buffer(LOG_RFC5444_W, &sock, t->interface, ptr, len, "Outgoing RFC5444 packet to",
    "Error while parsing outgoing RFC5444 packet to");

  if (_block_output) {
    OONF_DEBUG(LOG_RFC5444, "Output blocked");
    return;
  }

  oonf_packet_send_managed(&t->interface->_socket, &sock, ptr, len);
}

/**
 * Handle forwarding of rfc5444 messages
 * @param context RFC5444 tlvblock reader context
 * @param buffer message to be forwarded
 * @param length length of message
 */
static void
_cb_forward_message(struct rfc5444_reader_tlvblock_context *context, const uint8_t *buffer, size_t length) {
  struct oonf_rfc5444_protocol *protocol;
  enum rfc5444_result result;

  /* get protocol to use for forwarding message */
  protocol = container_of(context->reader, struct oonf_rfc5444_protocol, reader);

  /* forward message */
  OONF_INFO(LOG_RFC5444, "Forwarding message type %u", context->msg_type);

  result = rfc5444_writer_forward_msg(&protocol->writer, context, buffer, length);
  if (result != RFC5444_OKAY && result != RFC5444_NO_MSGCREATOR) {
    OONF_WARN(LOG_RFC5444, "Error while forwarding message: %s (%d)", rfc5444_strerror(result), result);
  }
}

static void
_cb_msggen_notifier(struct rfc5444_writer_target *rfc5444target) {
  struct oonf_rfc5444_target *target;
  uint64_t interval;

  target = container_of(rfc5444target, struct oonf_rfc5444_target, rfc5444_target);
  if (!oonf_timer_is_active(&target->_aggregation)) {
    interval = target->interface->overwrite_aggregation_interval;
    if (!interval) {
      interval = target->interface->aggregation_interval;
    }

    /* activate aggregation timer */
    oonf_timer_start(&target->_aggregation, target->interface->aggregation_interval);
  }
}

/**
 * Selector for outgoing target
 * @param writer rfc5444 writer
 * @param target rfc5444 target
 * @param ptr custom pointer, contains rfc5444 target
 * @return true if target corresponds to selection
 */
static bool
_cb_single_target_selector(
  struct rfc5444_writer *writer __attribute__((unused)), struct rfc5444_writer_target *target, void *ptr) {
  struct oonf_rfc5444_target *t = ptr;

  return &t->rfc5444_target == target;
}

/**
 * Selector for outgoing target
 * @param writer rfc5444 writer
 * @param rfc5444_target rfc5444 target
 * @param ptr custom pointer, contains rfc5444 target
 * @return true if target corresponds to selection
 */
static bool
_cb_filtered_targets_selector(struct rfc5444_writer *writer, struct rfc5444_writer_target *rfc5444_target, void *ptr) {
  rfc5444_writer_targetselector userUseIf;
  struct oonf_rfc5444_target *target;
#ifdef OONF_LOG_INFO
  struct netaddr_str buf;
#endif

  userUseIf = ptr;
  target = container_of(rfc5444_target, struct oonf_rfc5444_target, rfc5444_target);

  /* check if socket can send data */
  if (!oonf_rfc5444_is_target_active(target)) {
    return false;
  }

  /* check if user deselected the target */
  if (!userUseIf(writer, rfc5444_target, NULL)) {
    return false;
  }

  /* create message */
  OONF_INFO(LOG_RFC5444, "Send message to protocol %s/target %s on interface %s", target->interface->protocol->name,
    netaddr_to_string(&buf, &target->dst), target->interface->name);

  return true;
}

/**
 * Internal memory allocation function for addrblock
 * @return pointer to cleared addrblock
 */
static struct rfc5444_reader_addrblock_entry *
_alloc_addrblock_entry(void) {
  return oonf_class_malloc(&_addrblock_memcookie);
}

/**
 * Internal memory allocation function for rfc5444_reader_tlvblock_entry
 * @return pointer to cleared rfc5444_reader_tlvblock_entry
 */
static struct rfc5444_reader_tlvblock_entry *
_alloc_tlvblock_entry(void) {
  return oonf_class_malloc(&_tlvblock_memcookie);
}

/**
 * Internal memory allocation function for rfc5444_writer_address
 * @return pointer to cleared rfc5444_writer_address
 */
static struct rfc5444_writer_address *
_alloc_address_entry(void) {
  return oonf_class_malloc(&_address_memcookie);
}

/**
 * Internal memory allocation function for rfc5444_writer_addrtlv
 * @return pointer to cleared rfc5444_writer_addrtlv
 */
static struct rfc5444_writer_addrtlv *
_alloc_addrtlv_entry(void) {
  return oonf_class_malloc(&_addrtlv_memcookie);
}

/**
 * Free an addrblock entry
 * @param addrblock addressblock to be freed
 */
static void
_free_addrblock_entry(struct rfc5444_reader_addrblock_entry *addrblock) {
  oonf_class_free(&_addrblock_memcookie, addrblock);
}

/**
 * Free a tlvblock entry
 * @param tlvblock tlvblock to be freed
 */
static void
_free_tlvblock_entry(struct rfc5444_reader_tlvblock_entry *tlvblock) {
  oonf_class_free(&_tlvblock_memcookie, tlvblock);
}

/**
 * Free an address
 * @param address address to be freed
 */
static void
_free_address_entry(struct rfc5444_writer_address *address) {
  oonf_class_free(&_address_memcookie, address);
}

/**
 * Free an address tlv entry
 * @param addrtlv address tlv entry to be freed
 */
static void
_free_addrtlv_entry(struct rfc5444_writer_addrtlv *addrtlv) {
  oonf_class_free(&_addrtlv_memcookie, addrtlv);
}

/**
 * Callback to add sequence number to outgoing RFC5444 packet
 * @param writer pointer to rfc5444 writer
 * @param rfc5444_target rfc5444 target where the packet will be sent to
 */
static void
_cb_add_seqno(struct rfc5444_writer *writer, struct rfc5444_writer_target *rfc5444_target) {
  struct oonf_rfc5444_target *target;
  bool seqno;

  target = container_of(rfc5444_target, struct oonf_rfc5444_target, rfc5444_target);

  seqno = target->_pktseqno_refcount > 0 || target->interface->protocol->_pktseqno_refcount > 0;

  rfc5444_writer_set_pkt_header(writer, rfc5444_target, seqno);
  if (seqno) {
    target->_pktseqno++;
    rfc5444_writer_set_pkt_seqno(writer, rfc5444_target, target->_pktseqno);
  }
}

/**
 * Timer callback for message aggregation
 * @param ptr timer instance that fired
 */
static void
_cb_aggregation_event(struct oonf_timer_instance *ptr) {
  struct oonf_rfc5444_target *target;

  target = container_of(ptr, struct oonf_rfc5444_target, _aggregation);

  rfc5444_writer_flush(&target->interface->protocol->writer, &target->rfc5444_target, false);
}

/**
 * Configuration has changed, handle the changes
 */
static void
_cb_cfg_rfc5444_changed(void) {
  struct _rfc5444_config config;
  int result;

  memset(&config, 0, sizeof(config));
  result = cfg_schema_tobin(&config, _rfc5444_section.post, _rfc5444_entries, ARRAYSIZE(_rfc5444_entries));
  if (result) {
    OONF_WARN(LOG_RFC5444, "Could not convert " CFG_RFC5444_SECTION " to binary (%d)", -(result + 1));
    return;
  }

  /* apply values */
  oonf_rfc5444_reconfigure_protocol(_rfc5444_protocol, config.port, config.ip_proto);
}

/**
 * Configuration has changed, handle the changes
 */
static void
_cb_cfg_interface_changed(void) {
  struct _rfc5444_if_config config;
  struct oonf_rfc5444_interface *interf;
  const char *ifname;
  char ifbuf[IF_NAMESIZE];
  int result;

  ifname = cfg_get_phy_if(ifbuf, _interface_section.section_name);

  interf = avl_find_element(&_rfc5444_protocol->_interface_tree, ifname, interf, _node);

  if (_interface_section.post == NULL) {
    /* this section has been removed */
    if (interf) {
      oonf_rfc5444_remove_interface(interf, NULL);
    }
    goto interface_changed_cleanup;
  }

  memset(&config, 0, sizeof(config));
  result = cfg_schema_tobin(&config, _interface_section.post, _interface_entries, ARRAYSIZE(_interface_entries));
  if (result) {
    OONF_WARN(LOG_RFC5444, "Could not convert %s '%s' to binary (%d)", _interface_section.type, ifname, -(result + 1));
    goto interface_changed_cleanup;
  }

  if (_interface_section.pre == NULL) {
    interf = oonf_rfc5444_add_interface(_rfc5444_protocol, NULL, ifname);
    if (interf == NULL) {
      OONF_WARN(LOG_RFC5444, "Could not generate interface '%s' for protocol '%s'", ifname, _rfc5444_protocol->name);
      goto interface_changed_cleanup;
    }
  }

  oonf_rfc5444_reconfigure_interface(interf, &config.sock);
  interf->aggregation_interval = config.aggregation_interval;

  /* fall through */
interface_changed_cleanup:
  oonf_packet_free_managed_config(&config.sock);
}

/**
 * Interface settings of a rfc5444 interface changed
 * @param managed managed socket which interface changed
 * @param changed true if socket addresses changed
 */
static void
_cb_interface_changed(struct oonf_packet_managed *managed, bool changed) {
  struct oonf_rfc5444_interface *interf;
  struct oonf_rfc5444_interface_listener *l;

  OONF_INFO(LOG_RFC5444, "RFC5444 Interface change event: %s", managed->_managed_config.interface);

  interf = container_of(managed, struct oonf_rfc5444_interface, _socket);

  if (changed) {
    _reconfigure_interface(interf, NULL, true);
  }

  list_for_each_element(&interf->_listener, l, _node) {
    l->cb_interface_changed(l, changed);
  }
}
