
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcore/oonf_logging.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_reader.h>
#include <oonf/generic/dlep/dlep_writer.h>
#include <oonf/generic/dlep/router/dlep_router_interface.h>
#include <oonf/generic/dlep/router/dlep_router_session.h>

#include <oonf/generic/dlep/ext_base_proto/proto.h>
#include <oonf/generic/dlep/ext_base_proto/proto_router.h>

static void _cb_init_router(struct dlep_session *);
static void _cb_apply_router(struct dlep_session *);
static void _cb_cleanup_router(struct dlep_session *);
static void _cb_create_peer_discovery(struct oonf_timer_instance *);

static enum dlep_parser_error _router_process_peer_offer(struct dlep_extension *, struct dlep_session *);
static enum dlep_parser_error _router_process_session_init_ack(struct dlep_extension *, struct dlep_session *);
static enum dlep_parser_error _router_process_destination_up(struct dlep_extension *, struct dlep_session *);
static enum dlep_parser_error _router_process_destination_up_ack(struct dlep_extension *, struct dlep_session *);
static enum dlep_parser_error _router_process_destination_down(struct dlep_extension *, struct dlep_session *);
static enum dlep_parser_error _router_process_destination_down_ack(struct dlep_extension *, struct dlep_session *);
static enum dlep_parser_error _router_process_destination_update(struct dlep_extension *, struct dlep_session *);
static enum dlep_parser_error _router_process_link_char_ack(struct dlep_extension *, struct dlep_session *);

static int _router_write_peer_discovery(struct dlep_extension *, struct dlep_session *session, const struct oonf_layer2_neigh_key *);
static int _router_write_session_init(struct dlep_extension *, struct dlep_session *session, const struct oonf_layer2_neigh_key *);

static struct dlep_extension_implementation _router_signals[] = {
  {
    .id = DLEP_UDP_PEER_DISCOVERY,
    .add_tlvs = _router_write_peer_discovery,
  },
  {
    .id = DLEP_UDP_PEER_OFFER,
    .process = _router_process_peer_offer,
  },
  {
    .id = DLEP_SESSION_INITIALIZATION,
    .add_tlvs = _router_write_session_init,
  },
  {
    .id = DLEP_SESSION_INITIALIZATION_ACK,
    .process = _router_process_session_init_ack,
  },
  {
    .id = DLEP_SESSION_UPDATE,
    .process = dlep_base_proto_process_session_update,
  },
  {
    .id = DLEP_SESSION_UPDATE_ACK,
    .process = dlep_base_proto_process_session_update_ack,
  },
  {
    .id = DLEP_SESSION_TERMINATION,
    .process = dlep_base_proto_process_session_termination,
  },
  {
    .id = DLEP_SESSION_TERMINATION_ACK,
    .process = dlep_base_proto_process_session_termination_ack,
  },
  {
    .id = DLEP_DESTINATION_UP,
    .process = _router_process_destination_up,
  },
  {
    .id = DLEP_DESTINATION_UP_ACK,
    .process = _router_process_destination_up_ack,
    .add_tlvs = dlep_base_proto_write_mac_only,
  },
  {
    .id = DLEP_DESTINATION_DOWN,
    .process = _router_process_destination_down,
  },
  {
    .id = DLEP_DESTINATION_DOWN_ACK,
    .process = _router_process_destination_down_ack,
    .add_tlvs = dlep_base_proto_write_mac_only,
  },
  {
    .id = DLEP_DESTINATION_UPDATE,
    .process = _router_process_destination_update,
  },
  {
    .id = DLEP_HEARTBEAT,
    .process = dlep_base_proto_process_heartbeat,
  },
  {
    .id = DLEP_LINK_CHARACTERISTICS_ACK,
    .process = _router_process_link_char_ack,
  },
};

static struct oonf_timer_class _peer_discovery_class = {
  .name = "dlep peer discovery",
  .callback = _cb_create_peer_discovery,
  .periodic = true,
};
static struct dlep_extension *_base;

/**
 * Initialize the routers DLEP base protocol extension
 */
void
dlep_base_proto_router_init(void) {
  _base = dlep_base_proto_init();
  dlep_extension_add_processing(_base, false, _router_signals, ARRAYSIZE(_router_signals));

  oonf_timer_add(&_peer_discovery_class);

  _base->cb_session_init_router = _cb_init_router;
  _base->cb_session_apply_router = _cb_apply_router;
  _base->cb_session_cleanup_router = _cb_cleanup_router;
}

/**
 * Callback to initialize the router session
 * @param session dlep session
 */
static void
_cb_init_router(struct dlep_session *session) {
  if (session->restrict_signal == DLEP_SESSION_INITIALIZATION_ACK) {
    /*
     * we are waiting for a Peer Init Ack,
     * so we need to send a Peer Init
     */
    dlep_session_generate_signal(session, DLEP_SESSION_INITIALIZATION, NULL);
    session->cb_send_buffer(session, 0);

    session->remote_heartbeat_interval = session->cfg.heartbeat_interval;
    dlep_base_proto_start_remote_heartbeat(session);
  }
}

/**
 * Callback to apply new network settings to a router session
 * @param session dlep session
 */
static void
_cb_apply_router(struct dlep_session *session) {
  OONF_DEBUG(session->log_source, "Initialize base router session");
  if (session->restrict_signal == DLEP_UDP_PEER_OFFER) {
    /*
     * we are waiting for a Peer Offer,
     * so we need to send Peer Discovery messages
     */
    session->local_event_timer.class = &_peer_discovery_class;

    OONF_DEBUG(session->log_source, "Activate discovery with interval %" PRIu64, session->cfg.discovery_interval);

    /* use the "local event" for the discovery timer */
    oonf_timer_set(&session->local_event_timer, session->cfg.discovery_interval);
  }
}

/**
 * Callback to cleanup the router session
 * @param session dlep session
 */
static void
_cb_cleanup_router(struct dlep_session *session) {
  struct oonf_layer2_net *l2net;

  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (l2net) {
    /* remove DLEP mark from interface */
    l2net->if_type = OONF_LAYER2_TYPE_UNDEFINED;
    l2net->if_dlep = false;

    /* and remove all DLEP data */
    oonf_layer2_net_remove(l2net, session->l2_origin);
  }

  dlep_base_proto_stop_timers(session);
}

/**
 * Callback to generate regular peer discovery signals
 * @param ptr timer instance that fired
 */
static void
_cb_create_peer_discovery(struct oonf_timer_instance *ptr) {
  struct dlep_session *session;

  session = container_of(ptr, struct dlep_session, local_event_timer);

  OONF_DEBUG(session->log_source, "Generate peer discovery");

  dlep_session_generate_signal(session, DLEP_UDP_PEER_DISCOVERY, NULL);
  session->cb_send_buffer(session, AF_INET);

  dlep_session_generate_signal(session, DLEP_UDP_PEER_DISCOVERY, NULL);
  session->cb_send_buffer(session, AF_INET6);
}

/**
 * Process the peer offer signal
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_peer_offer(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  struct dlep_router_if *router_if;
  union netaddr_socket local, remote;
  struct dlep_parser_value *value;
  const struct os_interface_ip *ip;
  const struct netaddr *result = NULL;
  struct netaddr addr;
  uint16_t port;
  bool tls;
  struct os_interface *ifdata;

  if (session->restrict_signal != DLEP_UDP_PEER_OFFER) {
    /* ignore unless we are in discovery mode */
    return DLEP_NEW_PARSER_OKAY;
  }

  /* optional peer type tlv */
  dlep_base_proto_print_peer_type(session);

  /* we are looking for a good address to respond to */
  result = NULL;

  /* remember interface data */
  ifdata = session->l2_listener.data;

  /* IPv6 offer */
  value = dlep_session_get_tlv_value(session, DLEP_IPV6_CONPOINT_TLV);
  while (value) {
    if (dlep_reader_ipv6_conpoint_tlv(&addr, &port, &tls, session, value)) {
      return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
    }

    if (tls) {
      /* TLS not supported at the moment */
    }
    else if (netaddr_is_in_subnet(&NETADDR_IPV6_LINKLOCAL, &addr) || result == NULL) {
      ip = os_interface_get_prefix_from_dst(&addr, ifdata);
      if (ip) {
        result = &ip->address;
        netaddr_socket_init(&remote, &addr, port, ifdata->index);
      }
    }
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* IPv4 offer */
  value = dlep_session_get_tlv_value(session, DLEP_IPV4_CONPOINT_TLV);
  while (value && !result) {
    if (dlep_reader_ipv4_conpoint_tlv(&addr, &port, &tls, session, value)) {
      return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
    }

    if (tls) {
      /* TLS not supported at the moment */
    }
    else {
      ip = os_interface_get_prefix_from_dst(&addr, ifdata);
      if (ip) {
        result = &ip->address;
        netaddr_socket_init(&remote, &addr, port, ifdata->index);
      }
    }
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* remote address of incoming session */
  if (!result) {
    netaddr_from_socket(&addr, &session->remote_socket);
    ip = os_interface_get_prefix_from_dst(&addr, ifdata);
    if (!ip) {
      /* no possible way to communicate */
      OONF_DEBUG(session->log_source, "No matching prefix for incoming connection found");
      return DLEP_NEW_PARSER_INTERNAL_ERROR;
    }
    result = &ip->address;
    netaddr_socket_init(&remote, &addr, port, ifdata->index);
  }

  /* initialize session */
  netaddr_socket_init(&local, result, 0, ifdata->index);

  router_if = dlep_router_get_by_layer2_if(ifdata->name);
  if (router_if && &router_if->interf.session == session) {
    dlep_router_add_session(router_if, &local, &remote);
    return DLEP_NEW_PARSER_OKAY;
  }
  /* ignore incoming offer, something is wrong */
  return DLEP_NEW_PARSER_INTERNAL_ERROR;
}

/**
 * Process the peer initialization ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_session_init_ack(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  struct dlep_parser_value *value;
  const uint8_t *ptr;
  int result;

  if (session->restrict_signal != DLEP_SESSION_INITIALIZATION_ACK) {
    /* ignore unless we are in initialization mode */
    return DLEP_NEW_PARSER_OKAY;
  }

  /* mandatory heartbeat tlv */
  if (dlep_reader_heartbeat_tlv(&session->remote_heartbeat_interval, session, NULL)) {
    OONF_INFO(session->log_source, "no heartbeat tlv, should not happen!");
    return DLEP_NEW_PARSER_MISSING_MANDATORY_TLV;
  }

  /* optional extension supported tlv */
  value = dlep_session_get_tlv_value(session, DLEP_EXTENSIONS_SUPPORTED_TLV);
  if (value) {
    ptr = dlep_session_get_tlv_binary(session, value);
    if (dlep_session_update_extensions(session, ptr, value->length / 2, true)) {
      return DLEP_NEW_PARSER_INTERNAL_ERROR;
    }
  }
  else if (dlep_session_update_extensions(session, NULL, 0, true)) {
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  l2net = oonf_layer2_net_add(session->l2_listener.name);
  if (!l2net) {
    return DLEP_NEW_PARSER_OUT_OF_MEMORY;
  }

  /* mark interface as DLEP */
  l2net->if_type = OONF_LAYER2_TYPE_WIRELESS;
  l2net->if_dlep = true;

  /* map user data into interface */
  result = dlep_reader_map_l2neigh_data(l2net->neighdata, session, _base);
  if (result) {
    OONF_INFO(session->log_source, "tlv mapping failed for extension %u: %u", ext->id, result);
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  OONF_DEBUG(session->log_source, "Remote heartbeat interval %" PRIu64, session->remote_heartbeat_interval);

  dlep_base_proto_start_local_heartbeat(session);
  dlep_base_proto_start_remote_heartbeat(session);

  dlep_base_proto_print_status(session);

  session->next_restrict_signal = DLEP_ALL_SIGNALS;

  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Process the destination up message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_destination_up(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;
  int result;
  struct oonf_layer2_neigh_key mac_lid;

  if (dlep_extension_get_l2_neighbor_key(&mac_lid, session)) {
    return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
  }

  l2net = oonf_layer2_net_add(session->l2_listener.name);
  if (!l2net) {
    if (dlep_session_generate_signal_status(
        session, DLEP_DESTINATION_UP_ACK, &mac_lid, DLEP_STATUS_REQUEST_DENIED, "Not enough memory")) {
      return DLEP_NEW_PARSER_INTERNAL_ERROR;
    }
    else {
      return DLEP_NEW_PARSER_OKAY;
    }
  }
  l2neigh = oonf_layer2_neigh_add_lid(l2net, &mac_lid);
  if (!l2neigh) {
    if (dlep_session_generate_signal_status(
      session, DLEP_DESTINATION_UP_ACK, &mac_lid, DLEP_STATUS_REQUEST_DENIED, "Not enough memory")) {
      return DLEP_NEW_PARSER_INTERNAL_ERROR;
    }
    else {
      return DLEP_NEW_PARSER_OKAY;
    }
  }

  result = dlep_reader_map_l2neigh_data(l2neigh->data, session, _base);
  if (result) {
    OONF_INFO(session->log_source, "tlv mapping failed for extension %u: %u", ext->id, result);
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  /* generate ACK */
  if (dlep_session_generate_signal_status (session, DLEP_DESTINATION_UP_ACK, &mac_lid, DLEP_STATUS_OKAY, "Success")) {
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Process the destination up ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_destination_up_ack(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  dlep_base_proto_print_status(session);
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Process the destination down message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_destination_down(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_neigh_key mac_lid;

  if (dlep_extension_get_l2_neighbor_key(&mac_lid, session)) {
    return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
  }

  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (!l2net) {
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  l2neigh = oonf_layer2_neigh_get_lid(l2net, &mac_lid);
  if (!l2neigh) {
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  /* remove layer2 neighbor */
  oonf_layer2_neigh_remove(l2neigh, session->l2_origin);

  /* generate ACK */
  if (dlep_session_generate_signal_status(session, DLEP_DESTINATION_DOWN_ACK, &mac_lid, DLEP_STATUS_OKAY, "Success")) {
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Process the destination down ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_destination_down_ack(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  dlep_base_proto_print_status(session);
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Process the destination update message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_destination_update(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_neigh_key mac_lid;
  int result;

  if (dlep_extension_get_l2_neighbor_key(&mac_lid, session)) {
    return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
  }

  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (!l2net) {
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  l2neigh = oonf_layer2_neigh_get_lid(l2net, &mac_lid);
  if (!l2neigh) {
    /* we did not get the destination up signal */
    return DLEP_NEW_PARSER_OKAY;
  }

  result = dlep_reader_map_l2neigh_data(l2neigh->data, session, _base);
  if (result) {
    OONF_INFO(session->log_source, "tlv mapping failed for extension %u: %u", ext->id, result);
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Process the link characteristic ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_router_process_link_char_ack(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  dlep_base_proto_print_status(session);
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Generate a peer discovery signal
 * @param ext (this) dlep extension
 * @param session dlep session
 * @param addr mac address the message should refer to
 * @return -1 if an error happened, 0 otherwise
 */
static int
_router_write_peer_discovery(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session,
  const struct oonf_layer2_neigh_key *addr __attribute__((unused))) {
  if (session->restrict_signal != DLEP_UDP_PEER_OFFER) {
    return -1;
  }
  return 0;
}

/**
 * Generate a peer init message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @param addr mac address the message should refer to
 * @return -1 if an error happened, 0 otherwise
 */
static int
_router_write_session_init(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session,
  const struct oonf_layer2_neigh_key *addr __attribute__((unused))) {
  const uint16_t *ext_ids;
  uint16_t ext_count;

  /* write supported extensions */
  ext_ids = dlep_extension_get_ids(&ext_count);
  if (ext_count) {
    dlep_writer_add_supported_extensions(&session->writer, ext_ids, ext_count);
  }

  dlep_writer_add_heartbeat_tlv(&session->writer, session->cfg.heartbeat_interval);

  /* TODO: report if radio has secured the medium */
  dlep_writer_add_peer_type_tlv(&session->writer, session->cfg.peer_type, false);

  return 0;
}
