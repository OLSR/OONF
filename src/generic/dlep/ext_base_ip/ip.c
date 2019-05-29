
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
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_interface.h>
#include <oonf/generic/dlep/dlep_reader.h>
#include <oonf/generic/dlep/dlep_writer.h>
#include <oonf/generic/dlep/radio/dlep_radio_interface.h>
#include <oonf/generic/dlep/radio/dlep_radio_session.h>
#include <oonf/generic/dlep/router/dlep_router_session.h>

#include <oonf/generic/dlep/ext_base_ip/ip.h>

struct _prefix_storage {
  struct netaddr prefix;

  struct avl_node _node;
};

static void _cb_session_init(struct dlep_session *session);
static void _cb_session_cleanup(struct dlep_session *session);
static int _write_session_update(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
static int _radio_write_destination_update(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
static enum dlep_parser_error _process_session_update(struct dlep_extension *ext, struct dlep_session *session);
static enum dlep_parser_error _router_process_destination_update(
  struct dlep_extension *ext, struct dlep_session *session);
static void _add_prefix(struct avl_tree *tree, struct netaddr *addr);

/* peer initialization ack/peer update/destination update */
static const uint16_t _ip_tlvs[] = {
  DLEP_IPV4_ADDRESS_TLV,
  DLEP_IPV4_SUBNET_TLV,
  DLEP_IPV6_ADDRESS_TLV,
  DLEP_IPV6_SUBNET_TLV,
};

static const uint16_t _ip_duplicate_tlvs[] = {
  DLEP_IPV4_ADDRESS_TLV,
  DLEP_IPV4_SUBNET_TLV,
  DLEP_IPV6_ADDRESS_TLV,
  DLEP_IPV6_SUBNET_TLV,
};

/* supported signals of this extension */
static struct dlep_extension_signal _signals[] = {
  {
    .id = DLEP_SESSION_INITIALIZATION,
    .supported_tlvs = _ip_tlvs,
    .supported_tlv_count = ARRAYSIZE(_ip_tlvs),
    .duplicate_tlvs = _ip_duplicate_tlvs,
    .duplicate_tlv_count = ARRAYSIZE(_ip_duplicate_tlvs),
    .add_radio_tlvs = _write_session_update,
    .process_radio = _process_session_update,
    .add_router_tlvs = _write_session_update,
    .process_router = _process_session_update,
  },
  {
    .id = DLEP_SESSION_INITIALIZATION_ACK,
    .supported_tlvs = _ip_tlvs,
    .supported_tlv_count = ARRAYSIZE(_ip_tlvs),
    .duplicate_tlvs = _ip_duplicate_tlvs,
    .duplicate_tlv_count = ARRAYSIZE(_ip_duplicate_tlvs),
    .add_radio_tlvs = _write_session_update,
    .process_radio = _process_session_update,
    .add_router_tlvs = _write_session_update,
    .process_router = _process_session_update,
  },
  {
    .id = DLEP_SESSION_UPDATE,
    .supported_tlvs = _ip_tlvs,
    .supported_tlv_count = ARRAYSIZE(_ip_tlvs),
    .duplicate_tlvs = _ip_duplicate_tlvs,
    .duplicate_tlv_count = ARRAYSIZE(_ip_duplicate_tlvs),
    .add_radio_tlvs = _write_session_update,
    .process_radio = _process_session_update,
    .add_router_tlvs = _write_session_update,
    .process_router = _process_session_update,
  },
  {
    .id = DLEP_DESTINATION_UP,
    .supported_tlvs = _ip_tlvs,
    .supported_tlv_count = ARRAYSIZE(_ip_tlvs),
    .duplicate_tlvs = _ip_duplicate_tlvs,
    .duplicate_tlv_count = ARRAYSIZE(_ip_duplicate_tlvs),
    .add_radio_tlvs = _radio_write_destination_update,
    .process_router = _router_process_destination_update,
  },
  {
    .id = DLEP_DESTINATION_UPDATE,
    .supported_tlvs = _ip_tlvs,
    .supported_tlv_count = ARRAYSIZE(_ip_tlvs),
    .duplicate_tlvs = _ip_duplicate_tlvs,
    .duplicate_tlv_count = ARRAYSIZE(_ip_duplicate_tlvs),
    .add_radio_tlvs = _radio_write_destination_update,
    .process_router = _router_process_destination_update,
  },
};

/* supported TLVs of this extension */
static struct dlep_extension_tlv _tlvs[] = {
  { DLEP_MAC_ADDRESS_TLV, 6, 8 },
  { DLEP_IPV4_ADDRESS_TLV, 5, 5 },
  { DLEP_IPV4_SUBNET_TLV, 6, 6 },
  { DLEP_IPV6_ADDRESS_TLV, 17, 17 },
  { DLEP_IPV6_SUBNET_TLV, 18, 18 },
};

/* DLEP base extension, radio side */
static struct dlep_extension _base_ip = {
  .id = DLEP_EXTENSION_BASE_IP,
  .name = "base metric",

  .signals = _signals,
  .signal_count = ARRAYSIZE(_signals),
  .tlvs = _tlvs,
  .tlv_count = ARRAYSIZE(_tlvs),

  .cb_session_init_radio = _cb_session_init,
  .cb_session_init_router = _cb_session_init,

  .cb_session_cleanup_radio = _cb_session_cleanup,
  .cb_session_cleanup_router = _cb_session_cleanup,
};

static struct oonf_class _prefix_class = {
  .name = "dlep ip prefix",
  .size = sizeof(struct _prefix_storage),
};

/**
 * Initialize the base metric DLEP extension
 * @return this extension
 */
struct dlep_extension *
dlep_base_ip_init(void) {
  dlep_extension_add(&_base_ip);
  oonf_class_add(&_prefix_class);

  return &_base_ip;
}

void
dlep_base_ip_cleanup(void) {
  oonf_class_remove(&_prefix_class);
}

static void
_cb_session_init(struct dlep_session *session __attribute__((unused))) {
}

static void
_cb_session_cleanup(struct dlep_session *session) {
  struct dlep_local_neighbor *l2neigh;
  struct _prefix_storage *storage, *storage_it;

  /* remove all stored changes for neighbors */
  avl_for_each_element(&session->local_neighbor_tree, l2neigh, _node) {
    avl_for_each_element_safe(&l2neigh->_ip_prefix_modification, storage, _node, storage_it) {
      avl_remove(&l2neigh->_ip_prefix_modification, &storage->_node);
      oonf_class_free(&_prefix_class, storage);
    }
  }

  /* remove all stored changes for the local peer */
  avl_for_each_element_safe(&session->_ext_ip.prefix_modification, storage, _node, storage_it) {
    avl_remove(&session->_ext_ip.prefix_modification, &storage->_node);
    oonf_class_free(&_prefix_class, storage);
  }
}

static void
_handle_if_ip(struct dlep_session *session, struct netaddr *last_session_if_ip,
    const struct netaddr *first_if_ip, const struct netaddr *second_if_ip) {
  const struct netaddr *if_ip;

  if_ip = netaddr_is_unspec(first_if_ip) ? second_if_ip : first_if_ip;

  if (netaddr_cmp(last_session_if_ip, if_ip) == 0) {
    return;
  }

  if (!netaddr_is_unspec(last_session_if_ip)) {
    dlep_writer_add_ip_tlv(&session->writer, last_session_if_ip, false);
  }
  if (!netaddr_is_unspec(if_ip)) {
    dlep_writer_add_ip_tlv(&session->writer, if_ip, true);
  }
  memcpy(last_session_if_ip, if_ip, sizeof(*if_ip));
}

static int
_write_session_update(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session,
  const struct oonf_layer2_neigh_key *neigh __attribute__((unused))) {
  struct _prefix_storage *storage, *storage_it;
  struct dlep_radio_session *radio_session;
  struct dlep_router_session *router_session;
  struct oonf_layer2_peer_address *peer_ip;
  struct oonf_layer2_net *l2net;
  struct os_interface *os_if;
  struct netaddr_str nbuf;

  /* first make sure defaults are set correctly */
  l2net = oonf_layer2_net_get(session->l2_listener.name);

  /* announce newly added interface prefixes */
  if (l2net) {
    avl_for_each_element(&l2net->local_peer_ips, peer_ip, _net_node) {
      if (peer_ip->origin == session->l2_default_origin
          || peer_ip->origin == session->l2_origin) {
        continue;
      }
      if (avl_find(&session->_ext_ip.prefix_modification, &peer_ip->ip)) {
        /* prefix already known to session */
        continue;
      }

      OONF_INFO(session->log_source, "New prefix '%s' for session update",
                netaddr_to_string(&nbuf, &peer_ip->ip));

      if (dlep_writer_add_ip_tlv(&session->writer, &peer_ip->ip, true)) {
        OONF_WARN(session->log_source, "Cannot add TLV for '%s' to session update",
          netaddr_to_string(&nbuf, &peer_ip->ip));
        return -1;
      }

      _add_prefix(&session->_ext_ip.prefix_modification, &peer_ip->ip);
    }
  }

  /* remove missing interface prefixes */
  avl_for_each_element_safe(&session->_ext_ip.prefix_modification, storage, _node, storage_it) {
    if (l2net) {
      peer_ip = oonf_layer2_net_get_local_ip(l2net, &storage->prefix);
      if (peer_ip != NULL
          && peer_ip->origin != session->l2_default_origin
          && peer_ip->origin != session->l2_origin) {
        /* prefix is still on interface */
        continue;
      }
    }

    OONF_INFO(session->log_source, "Removed prefix '%s' for session update",
              netaddr_to_string(&nbuf, &storage->prefix));

    if (dlep_writer_add_ip_tlv(&session->writer, &storage->prefix, false)) {
      OONF_WARN(session->log_source, "Cannot add TLV for '%s' to session update",
        netaddr_to_string(&nbuf, &storage->prefix));
      return -1;
    }

    avl_remove(&session->_ext_ip.prefix_modification, &storage->_node);
    oonf_class_free(&_prefix_class, storage);
  }

  /* also transmit IP interface addresses */
  radio_session = dlep_radio_get_session(session);
  if (radio_session) {
    os_if = radio_session->interface->interf.udp._if_listener.data;
    _handle_if_ip(session, &session->_ext_ip.if_ip_v4, os_if->if_linklocal_v4, os_if->if_v4);
    _handle_if_ip(session, &session->_ext_ip.if_ip_v6, os_if->if_linklocal_v6, os_if->if_v6);
  }
  router_session = dlep_router_get_session(session);
  if (router_session) {
    os_if = router_session->interface->interf.udp._if_listener.data;
    _handle_if_ip(session, &session->_ext_ip.if_ip_v4, os_if->if_linklocal_v4, os_if->if_v4);
    _handle_if_ip(session, &session->_ext_ip.if_ip_v6, os_if->if_linklocal_v6, os_if->if_v6);
  }

  return 0;
}

static int
_radio_write_destination_update(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session,
    const struct oonf_layer2_neigh_key *neigh) {
  struct dlep_local_neighbor *dlep_neigh;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_neighbor_address *l2neigh_ip;

  struct _prefix_storage *storage, *storage_it;

  union oonf_layer2_neigh_key_str nkbuf;
  struct netaddr_str nbuf1;

  dlep_neigh = dlep_session_get_local_neighbor(session, neigh);
  if (!dlep_neigh) {
    OONF_WARN(session->log_source,
      "Could not find dlep_neighbor for neighbor %s",
      oonf_layer2_neigh_key_to_string(&nkbuf, neigh, true));
    return -1;
  }

  l2neigh = dlep_session_get_l2_from_neighbor(dlep_neigh);

  /* send every attached IP towards the router */
//  avl_for_each_element(&dlep_neigh->_ip_prefix_modification, storage, _node) {
  /* announce newly added interface prefixes */
  if (l2neigh) {
    avl_for_each_element(&l2neigh->remote_neighbor_ips, l2neigh_ip, _neigh_node) {
      if (avl_find(&dlep_neigh->_ip_prefix_modification, &l2neigh_ip->ip)) {
        /* prefix already known to neighbor */
        continue;
      }

      OONF_INFO(session->log_source, "New prefix '%s' for neighbor %s update",
                netaddr_to_string(&nbuf1, &l2neigh_ip->ip),
                oonf_layer2_neigh_key_to_string(&nkbuf, neigh, true)
               );

      if (dlep_writer_add_ip_tlv(&session->writer, &l2neigh_ip->ip, true)) {
        OONF_WARN(session->log_source, "Cannot add TLV for '%s' to neighbor update",
          netaddr_to_string(&nbuf1, &l2neigh_ip->ip));
        return -1;
      }

      _add_prefix(&dlep_neigh->_ip_prefix_modification, &l2neigh_ip->ip);
    }
  }

  /* remove missing interface prefixes */
  avl_for_each_element_safe(&dlep_neigh->_ip_prefix_modification, storage, _node, storage_it) {
    if (l2neigh && avl_find(&l2neigh->remote_neighbor_ips, &storage->prefix)) {
      /* prefix is still on neighbor */
      continue;
    }

    OONF_INFO(session->log_source, "Removed prefix '%s' for neighbor %s update",
              netaddr_to_string(&nbuf1, &storage->prefix),
              oonf_layer2_neigh_key_to_string(&nkbuf, neigh, true)
             );

    if (dlep_writer_add_ip_tlv(&session->writer, &storage->prefix, false)) {
      OONF_WARN(session->log_source, "Cannot add TLV for '%s' to neighbor update",
        netaddr_to_string(&nbuf1, &storage->prefix));
      return -1;
    }

    avl_remove(&dlep_neigh->_ip_prefix_modification, &storage->_node);
    oonf_class_free(&_prefix_class, storage);
  }
  return 0;
}

static void
_process_session_ip_tlvs(
  const struct oonf_layer2_origin *origin, struct oonf_layer2_net *l2net, struct netaddr *ip, bool add) {
  struct oonf_layer2_peer_address *l2addr;

  if (add) {
    oonf_layer2_net_add_ip(l2net, origin, ip);
  }
  else if ((l2addr = oonf_layer2_net_get_local_ip(l2net, ip))) {
    oonf_layer2_net_remove_ip(l2addr, origin);
  }
}

static enum dlep_parser_error
_process_session_update(struct dlep_extension *ext __attribute((unused)), struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  struct netaddr ip;
  struct dlep_parser_value *value;
  bool add_ip;

  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (!l2net) {
    return 0;
  }

  /* ipv4 address */
  value = dlep_session_get_tlv_value(session, DLEP_IPV4_ADDRESS_TLV);
  while (value) {
    if (dlep_reader_ipv4_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_session_ip_tlvs(session->l2_origin, l2net, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* ipv6 address */
  value = dlep_session_get_tlv_value(session, DLEP_IPV6_ADDRESS_TLV);
  while (value) {
    if (dlep_reader_ipv6_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_session_ip_tlvs(session->l2_origin, l2net, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* ipv4 subnet */
  value = dlep_session_get_tlv_value(session, DLEP_IPV4_SUBNET_TLV);
  while (value) {
    if (dlep_reader_ipv4_subnet_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_session_ip_tlvs(session->l2_origin, l2net, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* ipv6 subnet */
  value = dlep_session_get_tlv_value(session, DLEP_IPV6_SUBNET_TLV);
  while (value) {
    if (dlep_reader_ipv6_subnet_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_session_ip_tlvs(session->l2_origin, l2net, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }
  return 0;
}

static void
_process_destination_ip_tlv(
  const struct oonf_layer2_origin *origin, struct oonf_layer2_neigh *l2neigh, struct netaddr *ip, bool add) {
  struct oonf_layer2_neighbor_address *l2addr;
  struct oonf_layer2_peer_address *peer_ip;
  int af;

  af = netaddr_get_address_family(ip);
  if (add) {
    if (!oonf_layer2_neigh_has_nexthop(l2neigh, af)) {
      avl_for_each_element(&l2neigh->network->local_peer_ips, peer_ip, _net_node) {
        if (netaddr_get_address_family(&peer_ip->ip) == af
            && netaddr_get_prefix_length(&peer_ip->ip) == netaddr_get_af_maxprefix(af)) {
          oonf_layer2_neigh_set_nexthop(l2neigh, &peer_ip->ip);
          break;
        }
      }
    }
    oonf_layer2_neigh_add_ip(l2neigh, origin, ip);
  }
  else if ((l2addr = oonf_layer2_neigh_get_remote_ip(l2neigh, ip))) {
    oonf_layer2_neigh_remove_ip(l2addr, origin);
  }
}

static enum dlep_parser_error
_router_process_destination_update(struct dlep_extension *ext __attribute((unused)), struct dlep_session *session) {
  struct oonf_layer2_neigh *l2neigh;
  struct netaddr ip;
  struct dlep_parser_value *value;
  bool add_ip;

  l2neigh = dlep_extension_get_l2_neighbor(session);
  if (!l2neigh) {
    return 0;
  }

  /* ipv4 address */
  value = dlep_session_get_tlv_value(session, DLEP_IPV4_ADDRESS_TLV);
  while (value) {
    if (dlep_reader_ipv4_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_destination_ip_tlv(session->l2_origin, l2neigh, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* ipv6 address */
  value = dlep_session_get_tlv_value(session, DLEP_IPV6_ADDRESS_TLV);
  while (value) {
    if (dlep_reader_ipv6_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_destination_ip_tlv(session->l2_origin, l2neigh, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* ipv4 subnet */
  value = dlep_session_get_tlv_value(session, DLEP_IPV4_SUBNET_TLV);
  while (value) {
    if (dlep_reader_ipv4_subnet_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_destination_ip_tlv(session->l2_origin, l2neigh, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }

  /* ipv6 subnet */
  value = dlep_session_get_tlv_value(session, DLEP_IPV6_SUBNET_TLV);
  while (value) {
    if (dlep_reader_ipv6_subnet_tlv(&ip, &add_ip, session, value)) {
      return -1;
    }
    _process_destination_ip_tlv(session->l2_origin, l2neigh, &ip, add_ip);
    value = dlep_session_get_next_tlv_value(session, value);
  }
  return 0;
}

static void
_add_prefix(struct avl_tree *tree, struct netaddr *addr) {
  struct _prefix_storage *storage;

  storage = avl_find_element(tree, addr, storage, _node);
  if (storage) {
    return;
  }

  storage = oonf_class_malloc(&_prefix_class);
  if (!storage) {
    return;
  }

  /* copy key and put into tree */
  memcpy(&storage->prefix, addr, sizeof(*addr));
  storage->_node.key = &storage->prefix;
  avl_insert(tree, &storage->_node);
}
