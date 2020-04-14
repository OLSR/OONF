
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
#include <oonf/libcommon/json.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libconfig/cfg_validate.h>
#include <oonf/libconfig/cfg_help.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/os_interface.h>

#include <oonf/base/oonf_layer2.h>

/* Definitions */
#define LOG_LAYER2 _oonf_layer2_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _net_remove(struct oonf_layer2_net *l2net);
static void _neigh_remove(struct oonf_layer2_neigh *l2neigh);

/* subsystem definition */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
};

static struct oonf_subsystem _oonf_layer2_subsystem = {
  .name = OONF_LAYER2_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_oonf_layer2_subsystem);

/* layer2 neighbor metadata */
static const struct oonf_layer2_metadata _metadata_neigh[OONF_LAYER2_NEIGH_COUNT] = {
  [OONF_LAYER2_NEIGH_TX_SIGNAL] = { .key = "tx_signal", .type = OONF_LAYER2_INTEGER_DATA, .unit = "dBm", .scaling = 1000 },
  [OONF_LAYER2_NEIGH_RX_SIGNAL] = { .key = "rx_signal", .type = OONF_LAYER2_INTEGER_DATA, .unit = "dBm", .scaling = 1000 },
  [OONF_LAYER2_NEIGH_TX_SNR] = { .key = "tx_snr", .type = OONF_LAYER2_INTEGER_DATA, .unit = "dB", .scaling = 1000 },
  [OONF_LAYER2_NEIGH_RX_SNR] = { .key = "rx_snr", .type = OONF_LAYER2_INTEGER_DATA, .unit = "dB", .scaling = 1000 },
  [OONF_LAYER2_NEIGH_TX_BITRATE] = { .key = "tx_bitrate", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_BITRATE] = { .key = "rx_bitrate", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_MAX_BITRATE] = { .key = "tx_max_bitrate", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_MAX_BITRATE] = { .key = "rx_max_bitrate", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_BYTES] = { .key = "tx_bytes", .type = OONF_LAYER2_INTEGER_DATA, .unit = "byte", .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_BYTES] = { .key = "rx_bytes", .type = OONF_LAYER2_INTEGER_DATA, .unit = "byte", .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_FRAMES] = { .key = "tx_frames", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_FRAMES] = { .key = "rx_frames", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_THROUGHPUT] = { .key = "tx_throughput", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_THROUGHPUT] = { .key = "rx_throughput", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_RETRIES] = { .key = "tx_retries", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_RETRIES] = { .key = "rx_retries", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_FAILED] = { .key = "tx_failed", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_FAILED] = { .key = "rx_failed", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_RLQ] = { .key = "tx_rlq", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_RLQ] = { .key = "rx_rlq", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_BC_BITRATE] = { .key = "rx_bc_bitrate", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_BC_LOSS] = { .key = "rx_bc_loss", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 100 },
  [OONF_LAYER2_NEIGH_LATENCY] = { .key = "latency", .type = OONF_LAYER2_INTEGER_DATA, .unit = "s", .scaling = 1000000 },
  [OONF_LAYER2_NEIGH_RESOURCES] = { .key = "resources", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_RADIO_HOPCOUNT] = { .key = "radio_hopcount", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_IP_HOPCOUNT] = { .key = "ip_hopcount", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE] = { .key = "tx_error_rate", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
  [OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE] = { .key = "rx_error_rate", .type = OONF_LAYER2_INTEGER_DATA, .scaling = 1 },
};

/* layer2 network metadata */
static const struct oonf_layer2_metadata _metadata_net[OONF_LAYER2_NET_COUNT] = {
  [OONF_LAYER2_NET_FREQUENCY_1] = { .key = "frequency1", .type = OONF_LAYER2_INTEGER_DATA, .unit = "Hz", .scaling = 1 },
  [OONF_LAYER2_NET_FREQUENCY_2] = { .key = "frequency2", .type = OONF_LAYER2_INTEGER_DATA, .unit = "Hz", .scaling = 1 },
  [OONF_LAYER2_NET_BANDWIDTH_1] = { .key = "bandwidth1", .type = OONF_LAYER2_INTEGER_DATA, .unit = "Hz", .scaling = 1 },
  [OONF_LAYER2_NET_BANDWIDTH_2] = { .key = "bandwidth2", .type = OONF_LAYER2_INTEGER_DATA, .unit = "Hz", .scaling = 1 },
  [OONF_LAYER2_NET_NOISE] = { .key = "noise", .type = OONF_LAYER2_INTEGER_DATA, .unit = "dBm", .scaling = 1000 },
  [OONF_LAYER2_NET_CHANNEL_ACTIVE] = { .key = "ch_active",
    .type = OONF_LAYER2_INTEGER_DATA,
    .unit = "s",
    .scaling = 1000000000 },
  [OONF_LAYER2_NET_CHANNEL_BUSY] = { .key = "ch_busy", .type = OONF_LAYER2_INTEGER_DATA, .unit = "s", .scaling = 1000000000 },
  [OONF_LAYER2_NET_CHANNEL_RX] = { .key = "ch_rx", .type = OONF_LAYER2_INTEGER_DATA, .unit = "s", .scaling = 1000000000 },
  [OONF_LAYER2_NET_CHANNEL_TX] = { .key = "ch_tx", .type = OONF_LAYER2_INTEGER_DATA, .unit = "s", .scaling = 1000000000 },
  [OONF_LAYER2_NET_TX_BC_BITRATE] = { .key = "tx_bc_bitrate", .type = OONF_LAYER2_INTEGER_DATA, .unit = "bit/s", .scaling = 1 },
  [OONF_LAYER2_NET_MTU] = { .key = "mtu", .type = OONF_LAYER2_INTEGER_DATA, .unit = "byte", .scaling = 1 },
  [OONF_LAYER2_NET_MCS_BY_PROBING] = { .key = "mcs_by_probing", .type = OONF_LAYER2_BOOLEAN_DATA },
  [OONF_LAYER2_NET_RX_ONLY_UNICAST] = { .key = "rx_only_unicast", .type = OONF_LAYER2_BOOLEAN_DATA },
  [OONF_LAYER2_NET_TX_ONLY_UNICAST] = { .key = "tx_only_unicast", .type = OONF_LAYER2_BOOLEAN_DATA },
  [OONF_LAYER2_NET_RADIO_MULTIHOP] = { .key = "radio_multihop", .type = OONF_LAYER2_BOOLEAN_DATA },
  [OONF_LAYER2_NET_BAND_UP_DOWN] = { .key = "band_updown", .type = OONF_LAYER2_BOOLEAN_DATA },
  [OONF_LAYER2_NET_IPV4_LOCAL_DNS] = { .key = "local_ipv4_dns", .type = OONF_LAYER2_SOCKET_DATA, .net_flags = OONF_LAYER2_IPV4_DATA | OONF_LAYER2_UNSPEC_DATA },
  [OONF_LAYER2_NET_IPV6_LOCAL_DNS] = { .key = "local_ipv6_dns", .type = OONF_LAYER2_SOCKET_DATA, .net_flags = OONF_LAYER2_IPV6_DATA | OONF_LAYER2_UNSPEC_DATA },
  [OONF_LAYER2_NET_IPV4_REMOTE_DNS] = { .key = "remote_ipv4_dns", .type = OONF_LAYER2_SOCKET_DATA, .net_flags = OONF_LAYER2_IPV4_DATA | OONF_LAYER2_UNSPEC_DATA },
  [OONF_LAYER2_NET_IPV6_REMOTE_DNS] = { .key = "remote_ipv6_dns", .type = OONF_LAYER2_SOCKET_DATA, .net_flags = OONF_LAYER2_IPV6_DATA | OONF_LAYER2_UNSPEC_DATA },
};

static const char *_network_type[OONF_LAYER2_TYPE_COUNT] = {
  [OONF_LAYER2_TYPE_UNDEFINED] = "undefined",
  [OONF_LAYER2_TYPE_WIRELESS] = "wireless",
  [OONF_LAYER2_TYPE_ETHERNET] = "ethernet",
  [OONF_LAYER2_TYPE_TUNNEL] = "tunnel",
};

static const char *_data_comparators[OONF_LAYER2_DATA_CMP_COUNT] = {
  [OONF_LAYER2_DATA_CMP_EQUALS] = "==",
  [OONF_LAYER2_DATA_CMP_NOT_EQUALS] = "!=",
  [OONF_LAYER2_DATA_CMP_LESSER] = "<",
  [OONF_LAYER2_DATA_CMP_LESSER_OR_EQUALS] = "<=",
  [OONF_LAYER2_DATA_CMP_GREATER] = ">",
  [OONF_LAYER2_DATA_CMP_GREATER_OR_EQUALS] = ">=",
};

static const char *_data_types[OONF_LAYER2_DATA_TYPE_COUNT] = {
  [OONF_LAYER2_INTEGER_DATA] = "integer",
  [OONF_LAYER2_BOOLEAN_DATA] = "boolean",
  [OONF_LAYER2_NETWORK_DATA] = "network",
  [OONF_LAYER2_SOCKET_DATA]  = "socket",
};

/* infrastructure for l2net/l2neigh tree */
static struct oonf_class _l2network_class = {
  .name = LAYER2_CLASS_NETWORK,
  .size = sizeof(struct oonf_layer2_net),
};
static struct oonf_class _l2neighbor_class = {
  .name = LAYER2_CLASS_NEIGHBOR,
  .size = sizeof(struct oonf_layer2_neigh),
};
static struct oonf_class _l2dst_class = {
  .name = LAYER2_CLASS_DESTINATION,
  .size = sizeof(struct oonf_layer2_destination),
};
static struct oonf_class _l2net_addr_class = {
  .name = LAYER2_CLASS_NETWORK_ADDRESS,
  .size = sizeof(struct oonf_layer2_peer_address),
};
static struct oonf_class _l2neigh_addr_class = {
  .name = LAYER2_CLASS_NEIGHBOR_ADDRESS,
  .size = sizeof(struct oonf_layer2_neighbor_address),
};
static struct oonf_class _lid_class = {
  .name = LAYER2_CLASS_LID,
  .size = sizeof(struct oonf_layer2_lid),
};

static struct avl_tree _oonf_layer2_net_tree;

static struct avl_tree _oonf_originator_tree;

static struct avl_tree _local_peer_ips_tree;

static struct avl_tree _lid_tree;

static uint32_t _lid_originator_count;

/**
 * Subsystem constructor
 * @return always returns 0
 */
static int
_init(void) {
  oonf_class_add(&_l2network_class);
  oonf_class_add(&_l2neighbor_class);
  oonf_class_add(&_l2dst_class);
  oonf_class_add(&_l2net_addr_class);
  oonf_class_add(&_l2neigh_addr_class);
  oonf_class_add(&_lid_class);

  avl_init(&_oonf_layer2_net_tree, avl_comp_strcasecmp, false);
  avl_init(&_oonf_originator_tree, avl_comp_strcasecmp, false);
  avl_init(&_local_peer_ips_tree, avl_comp_netaddr, true);
  avl_init(&_lid_tree, avl_comp_netaddr, false);

  _lid_originator_count = 0;
  return 0;
}

/**
 * Subsystem destructor
 */
static void
_cleanup(void) {
  struct oonf_layer2_net *l2net, *l2n_it;
  struct oonf_layer2_lid *lid, *lid_it;

  avl_for_each_element_safe(&_oonf_layer2_net_tree, l2net, _node, l2n_it) {
    _net_remove(l2net);
  }
  avl_for_each_element_safe(&_lid_tree, lid, _node, lid_it) {
    avl_remove(&_lid_tree, &lid->_node);
    oonf_class_free(&_lid_class, lid);
  }

  oonf_class_remove(&_lid_class);
  oonf_class_remove(&_l2neigh_addr_class);
  oonf_class_remove(&_l2net_addr_class);
  oonf_class_remove(&_l2dst_class);
  oonf_class_remove(&_l2neighbor_class);
  oonf_class_remove(&_l2network_class);
}

/**
 * Register a new data originator number for layer2 data
 * @param origin layer2 originator
 */
void
oonf_layer2_origin_add(struct oonf_layer2_origin *origin) {
  origin->_node.key = origin->name;
  avl_insert(&_oonf_originator_tree, &origin->_node);

  if (origin->lid) {
    origin->lid_index = _lid_originator_count;
    _lid_originator_count++;
  }
}

/**
 * Removes all layer2 data associated with this data originator
 * @param origin originator
 */
void
oonf_layer2_origin_remove(struct oonf_layer2_origin *origin) {
  struct oonf_layer2_net *l2net, *l2net_it;

  if (!avl_is_node_added(&origin->_node)) {
    return;
  }

  avl_for_each_element_safe(&_oonf_layer2_net_tree, l2net, _node, l2net_it) {
    oonf_layer2_net_remove(l2net, origin);
  }

  avl_remove(&_oonf_originator_tree, &origin->_node);
}

/**
 * Parse a string into a layer2 data object
 * @param value target buffer for layer2 data
 * @param meta metadata for layer2 data
 * @param input input string
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_layer2_data_parse_string(
  union oonf_layer2_value *value, const struct oonf_layer2_metadata *meta, const char *input) {
  memset(value, 0, sizeof(*value));

  switch (meta->type) {
    case OONF_LAYER2_INTEGER_DATA:
      return isonumber_to_s64(&value->integer, input, meta->scaling);

    case OONF_LAYER2_BOOLEAN_DATA:
      if (!cfg_is_bool(input)) {
        return -2;
      }
      value->boolean = cfg_get_bool(input);
      return 0;

    case OONF_LAYER2_NETWORK_DATA:
      if (netaddr_from_string(&value->addr, input)) {
        return -2;
      }
      if (netaddr_is_unspec(&value->addr)
          && (meta->net_flags & OONF_LAYER2_UNSPEC_DATA) == 0) {
        return -3;
      }
      if (netaddr_get_address_family(&value->addr) == AF_INET
          && (meta->net_flags & OONF_LAYER2_IPV4_DATA) == 0) {
        return -4;
      }
      if (netaddr_get_address_family(&value->addr) == AF_INET6
          && (meta->net_flags & OONF_LAYER2_IPV6_DATA) == 0) {
        return -5;
      }
      if (!netaddr_is_host(&value->addr)
          && (meta->net_flags & OONF_LAYER2_HOST_ONLY_DATA) != 0) {
        return -6;
      }
      return 0;

    case OONF_LAYER2_SOCKET_DATA:
      if (netaddr_socket_from_string(&value->socket, input)) {
        return -2;
      }
      if (netaddr_socket_is_unspec(&value->socket)
          && (meta->net_flags & OONF_LAYER2_UNSPEC_DATA) == 0) {
        return -3;
      }
      if (netaddr_socket_get_addressfamily(&value->socket) == AF_INET
          && (meta->net_flags & OONF_LAYER2_IPV4_DATA) == 0) {
        return -4;
      }
      if (netaddr_socket_get_addressfamily(&value->socket) == AF_INET6
          && (meta->net_flags & OONF_LAYER2_IPV6_DATA) == 0) {
        return -5;
      }
      return 0;

    default:
      return -1;
  }
}

/**
 * Convert a layer2 data object into a string representation
 * @param buffer destination string buffer
 * @param length length of string buffer
 * @param data layer2 data
 * @param meta layer2 metadata
 * @param raw true for raw conversion (switch of isoprefix conversion)
 * @return pointer to output buffer, NULL if an error happened
 */
const char *
oonf_layer2_data_to_string(
  char *buffer, size_t length, const struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta, bool raw) {
  struct isonumber_str iso_str;
  struct netaddr_str nbuf;

  switch (meta->type) {
    case OONF_LAYER2_INTEGER_DATA:
      if (!isonumber_from_s64(&iso_str, data->_value.integer, meta->unit, meta->scaling, raw)) {
        return NULL;
      }
      return strscpy(buffer, iso_str.buf, length);

    case OONF_LAYER2_BOOLEAN_DATA:
      return strscpy(buffer, json_getbool(data->_value.boolean), length);

    case OONF_LAYER2_NETWORK_DATA:
      return strscpy(buffer, netaddr_to_string(&nbuf, &data->_value.addr), length);

    case OONF_LAYER2_SOCKET_DATA:
      return strscpy(buffer, netaddr_socket_to_string(&nbuf, &data->_value.socket), length);

    default:
      return NULL;
  }
}

/**
 * (Over)write the value of a layer2 data object
 * @param l2data layer2 data object
 * @param origin origin of new data
 * @param meta metainformation of data
 * @param input new data value
 * @return true if data changed, false otherwise
 */
bool
oonf_layer2_data_set(struct oonf_layer2_data *l2data, const struct oonf_layer2_origin *origin,
  const struct oonf_layer2_metadata *meta, const union oonf_layer2_value *input) {
  bool changed = false;

  if (meta == NULL) {
    OONF_ASSERT(l2data->_meta != NULL, LOG_LAYER2, "Tried to set layer2 data without metadata (origin: %s)", origin->name);
    meta = l2data->_meta;
  }
  if (l2data->_meta == NULL || l2data->_origin == NULL || l2data->_origin == origin ||
      l2data->_origin->priority < origin->priority) {
    changed = l2data->_meta != meta || memcmp(&l2data->_value, input, sizeof(*input)) != 0;
    memcpy(&l2data->_value, input, sizeof(*input));
    l2data->_meta = meta;
    l2data->_origin = origin;
  }
  return changed;
}

/**
 * Set the value of a layer-2 data object
 * @param l2data layer-2 data object
 * @param origin originator of value
 * @param integer new value for data object
 * @param scaling scaling of the fixpoint interger arithmetics, 0 for same as metadata
 * @return true if value was overwrite, false otherwise
 */
bool
oonf_layer2_data_set_int64(struct oonf_layer2_data *l2data, const struct oonf_layer2_origin *origin,
    const struct oonf_layer2_metadata *meta, int64_t integer, uint64_t scaling) {
  union oonf_layer2_value value = { 0 };

  if (meta == NULL) {
    OONF_ASSERT(l2data->_meta != NULL, LOG_LAYER2, "Tried to set layer2 data without metadata (origin: %s)", origin->name);
    meta = l2data->_meta;
  }
  if (scaling == 0) {
    value.integer = integer;
  }
  else if (scaling > meta->scaling) {
    value.integer = integer / (scaling / meta->scaling);
  }
  else {
    value.integer = integer * (meta->scaling / scaling);
  }

  return oonf_layer2_data_set(l2data, origin, meta, &value);
}

/**
 * Compare two layer2 data objects
 * @param left left parameter for comparator
 * @param right right parameter for comparator
 * @param comparator comparator type
 * @param data_type data type for comparison
 * @return comparator result, false if not valid
 *   (e.g. comparing different types of data)
 */
bool
oonf_layer2_data_compare(const union oonf_layer2_value *left, const union oonf_layer2_value *right,
  enum oonf_layer2_data_comparator_type comparator, enum oonf_layer2_data_type data_type) {
  int result;

  switch (data_type) {
    case OONF_LAYER2_INTEGER_DATA:
      if (left->integer > right->integer) {
        result = 1;
      }
      else if (left->integer < right->integer) {
        result = -1;
      }
      else {
        result = 0;
      }
      break;
    case OONF_LAYER2_BOOLEAN_DATA:
      result = memcmp(&left->boolean, &right->boolean, sizeof(left->boolean));
      break;
    case OONF_LAYER2_NETWORK_DATA:
      result = memcmp(&left->addr, &right->addr, sizeof(left->addr));
      break;
    case OONF_LAYER2_SOCKET_DATA:
      result = memcmp(&left->socket, &right->socket, sizeof(left->socket));
      break;
    default:
      return false;
  }

  switch (comparator) {
    case OONF_LAYER2_DATA_CMP_EQUALS:
      return result == 0;
    case OONF_LAYER2_DATA_CMP_NOT_EQUALS:
      return result != 0;
    case OONF_LAYER2_DATA_CMP_LESSER:
      return result < 0;
    case OONF_LAYER2_DATA_CMP_LESSER_OR_EQUALS:
      return result <= 0;
    case OONF_LAYER2_DATA_CMP_GREATER:
      return result > 0;
    case OONF_LAYER2_DATA_CMP_GREATER_OR_EQUALS:
      return result >= 0;
    default:
      return false;
  }
}

/**
 * Get comparator type from string
 * @param string string (C) representation of comparator
 * @return comparator type
 */
enum oonf_layer2_data_comparator_type
oonf_layer2_data_get_comparator(const char *string)
{
  enum oonf_layer2_data_comparator_type i;

  for (i = 0; i < OONF_LAYER2_DATA_CMP_COUNT; i++) {
    if (strcmp(string, _data_comparators[i]) == 0) {
      return i;
    }
  }
  return OONF_LAYER2_DATA_CMP_ILLEGAL;
}

/**
 * @param type layer2 comparator type
 * @return string representation of comparator
 */
const char *
oonf_layer2_data_get_comparator_string(enum oonf_layer2_data_comparator_type type) {
  return _data_comparators[type];
}

/**
 * @param meta type index of layer2 metadata
 * @return the string name of a layer2 data type
 */
const char *
oonf_layer2_data_get_type_string(const struct oonf_layer2_metadata *meta) {
  static const char NONE[] = "NONE";
  if (!meta) {
    return NONE;
  }
  return _data_types[meta->type];
}

/**
 * Add a layer-2 network to the database
 * @param ifname name of interface
 * @return layer-2 network object
 */
struct oonf_layer2_net *
oonf_layer2_net_add(const char *ifname) {
  struct oonf_layer2_net *l2net;
  enum oonf_layer2_network_index netidx;
  enum oonf_layer2_neighbor_index neighidx;

  if (!ifname) {
    return NULL;
  }

  l2net = avl_find_element(&_oonf_layer2_net_tree, ifname, l2net, _node);
  if (l2net) {
    return l2net;
  }

  l2net = oonf_class_malloc(&_l2network_class);
  if (!l2net) {
    return NULL;
  }

  /* initialize key */
  strscpy(l2net->name, ifname, sizeof(l2net->name));

  /* add to global l2net tree */
  l2net->_node.key = l2net->name;
  avl_insert(&_oonf_layer2_net_tree, &l2net->_node);

  /* initialize tree of neighbors, ips and proxies */
  avl_init(&l2net->neighbors, oonf_layer2_avlcmp_neigh_key, false);
  avl_init(&l2net->local_peer_ips, avl_comp_netaddr, false);
  avl_init(&l2net->remote_neighbor_ips, avl_comp_netaddr, true);

  /* initialize interface listener */
  l2net->if_listener.name = l2net->name;
  os_interface_add(&l2net->if_listener);

  /* initialize data sections */
  for (netidx=0; netidx<OONF_LAYER2_NET_COUNT; netidx++) {
    l2net->data[netidx]._meta = oonf_layer2_net_metadata_get(netidx);
  }
  for (neighidx=0; neighidx<OONF_LAYER2_NEIGH_COUNT; neighidx++) {
    l2net->neighdata[neighidx]._meta = oonf_layer2_neigh_metadata_get(neighidx);
  }

  oonf_class_event(&_l2network_class, l2net, OONF_OBJECT_ADDED);

  return l2net;
}

/**
 * Remove all data objects of a certain originator from a layer-2 network
 * object.
 * @param l2net layer-2 addr object
 * @param origin originator number
 * @param cleanup_neigh true to cleanup neighbor data too
 * @return true if a value was removed, false otherwise
 */
bool
oonf_layer2_net_cleanup(struct oonf_layer2_net *l2net, const struct oonf_layer2_origin *origin, bool cleanup_neigh) {
  struct oonf_layer2_peer_address *l2peer, *l2peer_it;
  struct oonf_layer2_neigh *l2neigh;
  bool changed = false;
  int i;

  avl_for_each_element_safe(&l2net->local_peer_ips, l2peer, _net_node, l2peer_it) {
    if (!oonf_layer2_net_remove_ip(l2peer, origin)) {
      changed = true;
    }
  }

  for (i = 0; i < OONF_LAYER2_NET_COUNT; i++) {
    if (l2net->data[i]._origin == origin) {
      oonf_layer2_data_reset(&l2net->data[i]);
      changed = true;
    }
  }
  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    if (l2net->neighdata[i]._origin == origin) {
      oonf_layer2_data_reset(&l2net->neighdata[i]);
      changed = true;
    }
  }

  if (cleanup_neigh) {
    avl_for_each_element(&l2net->neighbors, l2neigh, _node) {
      changed |= oonf_layer2_neigh_cleanup(l2neigh, origin);
    }
  }
  return changed;
}

/**
 * Remove all information of a certain originator from a layer-2 addr
 * object. Remove the object if its empty and has no neighbors anymore.
 * @param l2net layer-2 addr object
 * @param origin originator identifier
 * @return true if something changed, false otherwise
 */
bool
oonf_layer2_net_remove(struct oonf_layer2_net *l2net, const struct oonf_layer2_origin *origin) {
  struct oonf_layer2_neigh *l2neigh, *l2neigh_it;
  bool changed = false;

  if (!avl_is_node_added(&l2net->_node)) {
    return false;
  }

  avl_for_each_element_safe(&l2net->neighbors, l2neigh, _node, l2neigh_it) {
    if (oonf_layer2_neigh_remove(l2neigh, origin)) {
      changed = true;
    }
  }

  if (oonf_layer2_net_cleanup(l2net, origin, false)) {
    changed = true;
  }

  if (changed) {
    oonf_layer2_net_commit(l2net);
  }
  return changed;
}

/**
 * Commit all changes to a layer-2 addr object. This might remove the
 * object from the database if all data has been removed from the object.
 * @param l2net layer-2 addr object
 * @return true if the object has been removed, false otherwise
 */
bool
oonf_layer2_net_commit(struct oonf_layer2_net *l2net) {
  size_t i;

  if (l2net->local_peer_ips.count > 0) {
    oonf_class_event(&_l2network_class, l2net, OONF_OBJECT_CHANGED);
    return false;
  }
  
  if (l2net->neighbors.count > 0) {
    oonf_class_event(&_l2network_class, l2net, OONF_OBJECT_CHANGED);
    return false;
  }

  for (i = 0; i < OONF_LAYER2_NET_COUNT; i++) {
    if (oonf_layer2_data_has_value(&l2net->data[i])) {
      oonf_class_event(&_l2network_class, l2net, OONF_OBJECT_CHANGED);
      return false;
    }
  }

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    if (oonf_layer2_data_has_value(&l2net->neighdata[i])) {
      oonf_class_event(&_l2network_class, l2net, OONF_OBJECT_CHANGED);
      return false;
    }
  }

  _net_remove(l2net);
  return true;
}

/**
 * Relabel all network data (including neighbor data)
 * of one origin to another one
 * @param l2net layer2 network object
 * @param new_origin new origin
 * @param old_origin old origin to overwrite
 */
void
oonf_layer2_net_relabel(struct oonf_layer2_net *l2net, const struct oonf_layer2_origin *new_origin,
  const struct oonf_layer2_origin *old_origin) {
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_peer_address *peer_ip;
  size_t i;

  for (i = 0; i < OONF_LAYER2_NET_COUNT; i++) {
    if (oonf_layer2_data_get_origin(&l2net->data[i]) == old_origin) {
      oonf_layer2_data_set_origin(&l2net->data[i], new_origin);
    }
  }

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    if (oonf_layer2_data_get_origin(&l2net->neighdata[i]) == old_origin) {
      oonf_layer2_data_set_origin(&l2net->neighdata[i], new_origin);
    }
  }

  avl_for_each_element(&l2net->local_peer_ips, peer_ip, _net_node) {
    if (peer_ip->origin == old_origin) {
      peer_ip->origin = new_origin;
    }
  }

  avl_for_each_element(&l2net->neighbors, l2neigh, _node) {
    oonf_layer2_neigh_relabel(l2neigh, new_origin, old_origin);
  }
}

/**
 * Add an IP address or prefix to a layer-2 interface. This represents
 * an address of the local radio or modem.
 * @param l2net layer-2 network object
 * @param ip ip address or prefix
 * @return layer2 ip address object, NULL if out of memory
 */
struct oonf_layer2_peer_address *
oonf_layer2_net_add_ip(
  struct oonf_layer2_net *l2net, const struct oonf_layer2_origin *origin, const struct netaddr *ip) {
  struct oonf_layer2_peer_address *l2addr;

  l2addr = oonf_layer2_net_get_local_ip(l2net, ip);
  if (!l2addr) {
    l2addr = oonf_class_malloc(&_l2net_addr_class);
    if (!l2addr) {
      return NULL;
    }

    /* copy data */
    memcpy(&l2addr->ip, ip, sizeof(*ip));

    /* set back reference */
    l2addr->l2net = l2net;

    /* add to tree */
    l2addr->_net_node.key = &l2addr->ip;
    avl_insert(&l2net->local_peer_ips, &l2addr->_net_node);

    l2addr->_global_node.key = &l2addr->ip;
    avl_insert(&_local_peer_ips_tree, &l2addr->_global_node);

    l2addr->origin = origin;

    oonf_class_event(&_l2net_addr_class, l2addr, OONF_OBJECT_ADDED);
  }
  else {
    l2addr->origin = origin;
  }
  return l2addr;
}

/**
 * Remove a peer IP address from a layer2 network
 * @param ip ip address or prefix
 * @param origin origin of IP address
 * @return 0 if IP was removed, -1 if it was registered to a different origin
 */
int
oonf_layer2_net_remove_ip(struct oonf_layer2_peer_address *ip, const struct oonf_layer2_origin *origin) {
  if (ip->origin != origin) {
    return -1;
  }

  oonf_class_event(&_l2net_addr_class, ip, OONF_OBJECT_REMOVED);

  avl_remove(&ip->l2net->local_peer_ips, &ip->_net_node);
  avl_remove(&_local_peer_ips_tree, &ip->_global_node);
  oonf_class_free(&_l2net_addr_class, ip);
  return 0;
}

/**
 * Look for the best matching prefix in all layer2 neighbor addresses
 * that contains a specific address
 * @param addr ip address to look for
 * @return layer2 neighbor address object, NULL if no match was found
 */
struct oonf_layer2_neighbor_address *
oonf_layer2_net_get_best_neighbor_match(const struct netaddr *addr) {
  struct oonf_layer2_neighbor_address *best_match, *l2addr;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_net *l2net;
  int prefix_length;

  prefix_length = 256;
  best_match = NULL;

  avl_for_each_element(&_oonf_layer2_net_tree, l2net, _node) {
    avl_for_each_element(&l2net->neighbors, l2neigh, _node) {
      avl_for_each_element(&l2neigh->remote_neighbor_ips, l2addr, _neigh_node) {
        if (netaddr_is_in_subnet(&l2addr->ip, addr) && netaddr_get_prefix_length(&l2addr->ip) < prefix_length) {
          best_match = l2addr;
          prefix_length = netaddr_get_prefix_length(&l2addr->ip);
        }
      }
    }
  }
  return best_match;
}

/**
 * Generate a layer2 key based on an originator and a MAC. Enumerate
 * new keys without explicitly storing them.
 * @param key destination buffer for key
 * @param origin originator for link-id creation
 * @param mac mac address part of key
 * @return -1 if an error happened, 0 otherwise
 */
int
oonf_layer2_neigh_generate_lid(struct oonf_layer2_neigh_key *key,
    struct oonf_layer2_origin *origin, const struct netaddr *mac) {
  struct oonf_layer2_lid *lid;
  uint32_t u32;

  if (!origin->lid) {
    return -1;
  }

  if (netaddr_get_address_family(mac) != AF_MAC48 && netaddr_get_address_family(mac) != AF_EUI64) {
    return -1;
  }

  if (!(lid = avl_find_element(&_lid_tree, mac, lid, _node))) {
    lid = oonf_class_malloc(&_lid_class);
    if (!lid) {
      return -1;
    }

    memcpy(&lid->mac, mac, sizeof(*mac));
    lid->_node.key = &lid->mac;
    avl_insert(&_lid_tree, &lid->_node);
    lid->next_id = 1;
  }

  memset(key, 0, sizeof(*key));

  /* copy mac */
  memcpy(&key->addr, mac, sizeof(*mac));

  /* TODO: make LID length configurable */

  /* generate new link-id */
  u32 = htonl(lid->next_id);
  memcpy(&key->link_id[0], &u32, 4);
  key->link_id_length = 4;

  /* keep track which originator orderer this LID */
  key->link_id[0] = origin->lid_index & 0xff;

  lid->next_id++;
  return 0;
}

/**
 * Add a layer-2 neighbor to a addr.
 * @param l2net layer-2 addr object
 * @param key unique key for neighbor
 * @return layer-2 neighbor object
 */
struct oonf_layer2_neigh *
oonf_layer2_neigh_add_lid(struct oonf_layer2_net *l2net, const struct oonf_layer2_neigh_key *key) {
  struct oonf_layer2_neigh *l2neigh;
  enum oonf_layer2_neighbor_index neighidx;

  if (netaddr_get_address_family(&key->addr) != AF_MAC48 && netaddr_get_address_family(&key->addr) != AF_EUI64) {
    return NULL;
  }

  l2neigh = oonf_layer2_neigh_get_lid(l2net, key);
  if (l2neigh) {
    return l2neigh;
  }

  l2neigh = oonf_class_malloc(&_l2neighbor_class);
  if (!l2neigh) {
    return NULL;
  }

  memcpy(&l2neigh->key, key, sizeof(*key));
  l2neigh->_node.key = &l2neigh->key;
  l2neigh->network = l2net;

  avl_insert(&l2net->neighbors, &l2neigh->_node);

  avl_init(&l2neigh->destinations, avl_comp_netaddr, false);
  avl_init(&l2neigh->remote_neighbor_ips, avl_comp_netaddr, false);

  /* initialize metadata */
  for (neighidx=0; neighidx<OONF_LAYER2_NEIGH_COUNT; neighidx++) {
    l2neigh->data[neighidx]._meta = oonf_layer2_neigh_metadata_get(neighidx);
  }

  oonf_class_event(&_l2neighbor_class, l2neigh, OONF_OBJECT_ADDED);

  return l2neigh;
}

/**
 * Remove all data objects of a certain originator from a layer-2 neighbor
 * object.
 * @param l2neigh layer-2 neighbor
 * @param origin originator number
 * @return true if a value was resetted, false otherwise
 */
bool
oonf_layer2_neigh_cleanup(struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *origin) {
  bool changed = false;
  int i;

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    if (l2neigh->data[i]._origin == origin) {
      oonf_layer2_data_reset(&l2neigh->data[i]);
      changed = true;
    }
  }
  return changed;
}

/**
 * Remove all information of a certain originator from a layer-2 neighbor
 * object. Remove the object if its empty.
 * @param l2neigh layer-2 neighbor object
 * @param origin originator number
 * @return true if something was change, false otherwise
 */
bool
oonf_layer2_neigh_remove(struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *origin) {
  struct oonf_layer2_destination *l2dst, *l2dst_it;
  struct oonf_layer2_neighbor_address *l2ip, *l2ip_it;

  bool changed = false;

  if (!avl_is_node_added(&l2neigh->_node)) {
    return false;
  }

  avl_for_each_element_safe(&l2neigh->destinations, l2dst, _node, l2dst_it) {
    if (l2dst->origin == origin) {
      oonf_layer2_destination_remove(l2dst);
      changed = true;
    }
  }

  avl_for_each_element_safe(&l2neigh->remote_neighbor_ips, l2ip, _neigh_node, l2ip_it) {
    if (oonf_layer2_neigh_remove_ip(l2ip, origin) == 0) {
      changed = true;
    }
  }

  if (oonf_layer2_neigh_cleanup(l2neigh, origin)) {
    changed = true;
  }

  if (changed) {
    oonf_layer2_neigh_commit(l2neigh);
  }
  return changed;
}

/**
 * Commit all changes to a layer-2 neighbor object. This might remove the
 * object from the database if all data has been removed from the object.
 * @param l2neigh layer-2 neighbor object
 * @return true if the object has been removed, false otherwise
 */
bool
oonf_layer2_neigh_commit(struct oonf_layer2_neigh *l2neigh) {
  size_t i;

  if (l2neigh->destinations.count > 0 || l2neigh->remote_neighbor_ips.count > 0) {
    oonf_class_event(&_l2neighbor_class, l2neigh, OONF_OBJECT_CHANGED);
    l2neigh->modified = OONF_LAYER2_NEIGH_MODIFY_NONE;
    return false;
  }

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    if (oonf_layer2_data_has_value(&l2neigh->data[i])) {
      oonf_class_event(&_l2neighbor_class, l2neigh, OONF_OBJECT_CHANGED);
      l2neigh->modified = OONF_LAYER2_NEIGH_MODIFY_NONE;
      return false;
    }
  }

  _neigh_remove(l2neigh);
  return true;
}

/**
 * Relabel all neighbor data of one origin to another one
 * @param l2neigh layer2 neighbor object
 * @param new_origin new origin
 * @param old_origin old origin to overwrite
 */
void
oonf_layer2_neigh_relabel(struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *new_origin,
  const struct oonf_layer2_origin *old_origin) {
  struct oonf_layer2_neighbor_address *neigh_ip;
  struct oonf_layer2_destination *l2dst;
  size_t i;

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    if (oonf_layer2_data_get_origin(&l2neigh->data[i]) == old_origin) {
      oonf_layer2_data_set_origin(&l2neigh->data[i], new_origin);
    }
  }

  avl_for_each_element(&l2neigh->remote_neighbor_ips, neigh_ip, _neigh_node) {
    if (neigh_ip->origin == old_origin) {
      neigh_ip->origin = new_origin;
    }
  }

  avl_for_each_element(&l2neigh->destinations, l2dst, _node) {
    if (l2dst->origin == old_origin) {
      l2dst->origin = new_origin;
    }
  }
}

/**
* Sets the (ip) next hop of a neighbor, you should call oonf_layer2_neigh_commit after a
* successful change.
* @param neigh layer2 neighbor
* @param nexthop next hop, should be IPv4 or IPv6
* @return -1 if nothing was changed, 0 if the next hop was updated.
*/
int
oonf_layer2_neigh_set_nexthop(struct oonf_layer2_neigh *neigh, const struct netaddr *nexthop) {
  enum oonf_layer2_neigh_mods mod;
  struct netaddr *nh;

  switch (netaddr_get_address_family(nexthop)) {
    case AF_INET:
      nh = &neigh->_next_hop_v4;
      mod = OONF_LAYER2_NEIGH_MODIFY_NEXTHOP_V4;
      break;
    case AF_INET6:
      nh = &neigh->_next_hop_v6;
      mod = OONF_LAYER2_NEIGH_MODIFY_NEXTHOP_V6;
      break;
    default:
      return -1;
  }

  if (memcmp(nh, nexthop, sizeof(*nexthop)) == 0) {
    return -1;
  }

  memcpy(nh, nexthop, sizeof(*nexthop));
  neigh->modified |= mod;
  return 0;
}


/**
 * Add an IP address or prefix to a layer-2 interface. This represents
 * an address of the local radio or modem.
 * @param l2neigh layer-2 neighbor object
 * @param origin layer2 data origin
 * @param ip ip address or prefix
 * @return layer2 ip address object, NULL if out of memory
 */
struct oonf_layer2_neighbor_address *
oonf_layer2_neigh_add_ip(
  struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *origin, const struct netaddr *ip) {
  struct oonf_layer2_neighbor_address *l2addr;

  l2addr = oonf_layer2_neigh_get_remote_ip(l2neigh, ip);
  if (l2addr) {
    l2addr->origin = origin;
    return l2addr;
  }

  l2addr = oonf_class_malloc(&_l2neigh_addr_class);
  if (!l2addr) {
    return NULL;
  }

  /* copy data */
  memcpy(&l2addr->ip, ip, sizeof(*ip));

  /* set back reference */
  l2addr->l2neigh = l2neigh;

  /* add to tree */
  l2addr->_neigh_node.key = &l2addr->ip;
  avl_insert(&l2neigh->remote_neighbor_ips, &l2addr->_neigh_node);
  l2addr->_net_node.key = &l2addr->ip;
  avl_insert(&l2neigh->network->remote_neighbor_ips, &l2addr->_net_node);

  /* remember originator */
  l2addr->origin = origin;

  oonf_class_event(&_l2neigh_addr_class, l2addr, OONF_OBJECT_ADDED);
  return l2addr;
}

/**
 * Remove a neighbor IP address from a layer2 neighbor
 * @param ip ip address or prefix
 * @param origin origin of IP address
 * @return 0 if IP was removed, -1 if it was registered to a different origin
 */
int
oonf_layer2_neigh_remove_ip(struct oonf_layer2_neighbor_address *ip, const struct oonf_layer2_origin *origin) {
  if (ip->origin != origin) {
    return -1;
  }

  oonf_class_event(&_l2neigh_addr_class, ip, OONF_OBJECT_REMOVED);

  avl_remove(&ip->l2neigh->remote_neighbor_ips, &ip->_neigh_node);
  avl_remove(&ip->l2neigh->network->remote_neighbor_ips, &ip->_net_node);
  oonf_class_free(&_l2neigh_addr_class, ip);
  return 0;
}

/**
 * add a layer2 destination (a MAC address behind a neighbor) to
 * the layer2 database
 * @param l2neigh layer2 neighbor of the destination
 * @param destination destination address
 * @param origin layer2 origin
 * @return layer2 destination, NULL if out of memory
 */
struct oonf_layer2_destination *
oonf_layer2_destination_add(
  struct oonf_layer2_neigh *l2neigh, const struct netaddr *destination, const struct oonf_layer2_origin *origin) {
  struct oonf_layer2_destination *l2dst;

  l2dst = oonf_layer2_destination_get(l2neigh, destination);
  if (l2dst) {
    return l2dst;
  }

  l2dst = oonf_class_malloc(&_l2dst_class);
  if (!l2dst) {
    return NULL;
  }

  /* copy data into destination storage */
  memcpy(&l2dst->destination, destination, sizeof(*destination));
  l2dst->origin = origin;

  /* add back-pointer */
  l2dst->neighbor = l2neigh;

  /* add to neighbor tree */
  l2dst->_node.key = &l2dst->destination;
  avl_insert(&l2neigh->destinations, &l2dst->_node);

  oonf_class_event(&_l2dst_class, l2dst, OONF_OBJECT_ADDED);
  return l2dst;
}

/**
 * Remove a layer2 destination
 * @param l2dst layer2 destination
 */
void
oonf_layer2_destination_remove(struct oonf_layer2_destination *l2dst) {
  if (!avl_is_node_added(&l2dst->_node)) {
    return;
  }
  oonf_class_event(&_l2dst_class, l2dst, OONF_OBJECT_REMOVED);

  avl_remove(&l2dst->neighbor->destinations, &l2dst->_node);
  oonf_class_free(&_l2dst_class, l2dst);
}

/**
 * Get neighbor specific data, either from neighbor or from the networks default
 * @param ifname name of interface
 * @param l2neigh_addr neighbor mac address
 * @param idx data index
 * @param get_default true to return default (net) data if no neighbor data available
 * @return pointer to linklayer data, NULL if no value available
 */
struct oonf_layer2_data *
oonf_layer2_neigh_query(const char *ifname, const struct netaddr *l2neigh_addr,
      enum oonf_layer2_neighbor_index idx, bool get_default) {
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_data *data;

  /* query layer2 database about neighbor */
  l2net = oonf_layer2_net_get(ifname);
  if (l2net == NULL) {
    return NULL;
  }

  /* look for neighbor specific data */
  l2neigh = oonf_layer2_neigh_get(l2net, l2neigh_addr);
  if (l2neigh != NULL) {
    data = &l2neigh->data[idx];
    if (oonf_layer2_data_has_value(data)) {
      return data;
    }
  }

  if (!get_default) {
    return NULL;
  }

  /* look for network specific default */
  data = &l2net->neighdata[idx];
  if (oonf_layer2_data_has_value(data)) {
    return data;
  }
  return NULL;
}

/**
 * Get neighbor specific data, add interface and neighbor if necessary
 * @param ifname name of interface
 * @param l2neigh_addr neighbor mac address
 * @param idx data index
 * @return pointer to linklayer data, NULL if no value available
 */
struct oonf_layer2_data *
oonf_layer2_neigh_add_path(const char *ifname, const struct netaddr *l2neigh_addr, enum oonf_layer2_neighbor_index idx) {
    struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;

  /* query layer2 database about neighbor */
  l2net = oonf_layer2_net_add(ifname);
  if (l2net == NULL) {
    return NULL;
  }

  /* look for neighbor specific data */
  l2neigh = oonf_layer2_neigh_add(l2net, l2neigh_addr);
  if (l2neigh == NULL) {
    return NULL;
  }

  return &l2neigh->data[idx];
}

/**
 * Get neighbor specific data, either from neighbor or from the networks default
 * @param l2neigh pointer to layer2 neighbor
 * @param idx data index
 * @return pointer to linklayer data, NULL if no value available
 */
struct oonf_layer2_data *
oonf_layer2_neigh_get_data(struct oonf_layer2_neigh *l2neigh, enum oonf_layer2_neighbor_index idx) {
  struct oonf_layer2_data *data;

  data = &l2neigh->data[idx];
  if (oonf_layer2_data_has_value(data)) {
    return data;
  }

  /* look for network specific default */
  data = &l2neigh->network->neighdata[idx];
  if (oonf_layer2_data_has_value(data)) {
    return data;
  }
  return NULL;
}

/**
 * get neighbor metric metadata
 * @param idx neighbor metric index
 * @return metadata object
 */
const struct oonf_layer2_metadata *
oonf_layer2_neigh_metadata_get(enum oonf_layer2_neighbor_index idx) {
  return &_metadata_neigh[idx];
}

/**
 * get network metric metadata
 * @param idx network metric index
 * @return metadata object
 */
const struct oonf_layer2_metadata *
oonf_layer2_net_metadata_get(enum oonf_layer2_network_index idx) {
  return &_metadata_net[idx];
}

/**
 * Callback for configuration choice of layer2 network key
 * @param idx index
 * @param unused not used
 * @return pointer to network key
 */
const char *
oonf_layer2_cfg_get_l2net_key(size_t idx, const void *unused __attribute__((unused))) {
  return _metadata_net[idx].key;
}

/**
 * Callback for configuration choice of layer2 neighbor key
 * @param idx index
 * @param unused not used
 * @return pointer to neighbor key
 */
const char *
oonf_layer2_cfg_get_l2neigh_key(size_t idx, const void *unused __attribute__((unused))) {
  return _metadata_neigh[idx].key;
}

/**
 * Callback for configuration choice of layer2 neighbor key
 * @param idx index
 * @param unused not used
 * @return pointer to neighbor key
 */
const char *
oonf_layer2_cfg_get_l2comp(size_t idx, const void *unused __attribute__((unused))) {
  return _data_comparators[idx];
}

/**
 * Schema entry validator for network addresses and prefixes.
 * See CFG_VALIDATE_LAYER2_NEIGH_MAC_LID() macros in oonf_layer2.h
 * @param entry pointer to schema entry
 * @param section_name name of section type and name
 * @param value value of schema entry
 * @param out pointer to autobuffer for validator output
 * @return 0 if validation found no problems, -1 otherwise
 */
int
oonf_layer2_validate_mac_lid(const struct cfg_schema_entry *entry,
    const char *section_name, const char *value, struct autobuf *out) {
  struct oonf_layer2_neigh_key key;
  int result;

  result = oonf_layer2_neigh_key_from_string(&key, value);
  switch (result) {
    case -1:
      cfg_append_printable_line(out,
          "Address '%s' for entry '%s' in section %s is too long",
          value, entry->key.entry, section_name);
      break;
    case -2:
      cfg_append_printable_line(out,
          "Link-id '%s' for entry '%s' in section %s is not hexadecimal or too long",
          value, entry->key.entry, section_name);
      break;
    case -3:
      cfg_append_printable_line(out,
          "Address '%s' for entry '%s' in section %s is not a valid address",
          value, entry->key.entry, section_name);
      break;
    case -4:
      cfg_append_printable_line(out,
          "Address '%s' for entry '%s' in section %s is not MAC48 or EUI64",
          value, entry->key.entry, section_name);
      break;
    default:
      return 0;
  }
  return -1;
}

/**
 * Help generator for layer2 neighbor lid parameter
 * See CFG_MAP_LAYER2_NEIGH_MAC_LID*() macros in oonf_layer2.h
 * @param entry pointer to schema entry
 * @param out pointer to autobuffer for validator output
 */
void
oonf_layer2_help_mac_lid(const struct cfg_schema_entry *entry __attribute__((unused)), struct autobuf *out) {
  static const int8_t AF_TYPES[] = { AF_MAC48, AF_EUI64 };
  cfg_help_netaddr(out, true, false, AF_TYPES, ARRAYSIZE(AF_TYPES));
  abuf_puts(out, CFG_HELP_INDENT_PREFIX "The parameter can also have an optional link id at the end,\n"
                 CFG_HELP_INDENT_PREFIX "a hexadecimal string separated by a ',' from the address in front of it.\n");
}

/**
 * Binary converter for layer2 neighbor keys including lid.
 * See CFG_MAP_LAYER2_NEIGH_MAC_LID() macro in oonf_layer2.h
 * @param s_entry pointer to configuration entry schema.
 * @param value pointer to value of configuration entry.
 * @param reference pointer to binary output buffer.
 * @return 0 if conversion succeeded, -1 otherwise.
 */
int
oonf_layer2_tobin_mac_lid(const struct cfg_schema_entry *s_entry, const struct const_strarray *value, void *reference) {
  if (s_entry->list) {
    /* we don't support direct list conversion to binary */
    return -1;
  }
  return oonf_layer2_neigh_key_from_string(reference, strarray_get_first_c(value));
}


/**
 * get text representation of network type
 * @param type network type
 * @return text representation
 */
const char *
oonf_layer2_net_get_type_name(enum oonf_layer2_network_type type) {
  return _network_type[type];
}

/**
 * get tree of layer2 networks
 * @return network tree
 */
struct avl_tree *
oonf_layer2_get_net_tree(void) {
  return &_oonf_layer2_net_tree;
}

/**
 * get tree of layer2 originators
 * @return originator tree
 */
struct avl_tree *
oonf_layer2_get_origin_tree(void) {
  return &_oonf_originator_tree;
}

/**
 * Compares two layer2 neighbor keys
 * @param p1 pointer to first neighbor key
 * @param p2 pointer to second neighbor key
 * @return result of memcmp comparison
 */
int
oonf_layer2_avlcmp_neigh_key(const void *p1, const void *p2) {
  const struct oonf_layer2_neigh_key *k1 = p1;
  const struct oonf_layer2_neigh_key *k2 = p2;

  return memcmp(k1, k2, sizeof(*k1));
}

/**
 * Converts a layer2 neighbor key into a string representation
 * @param buf buffer for output string
 * @param key layer2 neighbor key
 * @param show_mac true to show MAC and Link ID, false to only show LID
 * @return pointer to output string
 */
const char *
oonf_layer2_neigh_key_to_string(union oonf_layer2_neigh_key_str *buf,
    const struct oonf_layer2_neigh_key *key, bool show_mac) {
  static const char NONE[] = "-";
  size_t str_idx;
  uint8_t af;

  if (key == NULL) {
    return NONE;
  }

  af = netaddr_get_address_family(&key->addr);
  if (af != AF_MAC48 && af != AF_EUI64) {
    return NONE;
  }

  if (show_mac) {
    netaddr_to_string(&buf->nbuf, &key->addr);
  }
  else {
    buf->buf[0] = 0;
  }

  if (key->link_id_length == 0) {
    return buf->buf;
  }

  str_idx = strlen(buf->buf);

  if (show_mac) {
    buf->buf[str_idx++] = ',';
  }

  strhex_from_bin(&buf->buf[str_idx], sizeof(*buf) - str_idx, key->link_id, key->link_id_length);
  return buf->buf;
}

/**
 * Creates a layer2 neighbor key from a string.
 * @param key neighbor key
 * @param string string representation of neighbor key
 * @return negative if an error happened, 0 if everything is fine
 */
int
oonf_layer2_neigh_key_from_string(struct oonf_layer2_neigh_key *key, const char *string) {
  struct netaddr_str nbuf;
  const char *split, *addr;
  ssize_t len;

  memset(key, 0, sizeof(*key));
  split = strchr(string, ',');

  if (!split) {
    addr = string;
  }
  else {
    len = split - string;
    if (len > (ssize_t)(sizeof(nbuf))) {
      return -1;
    }

    strscpy(nbuf.buf, string, len+1);
    addr = nbuf.buf;

    split++;
    len = strhex_to_bin(key->link_id, sizeof(key->link_id), split);
    if (len < 0) {
      return -2;
    }
    key->link_id_length = len;
  }

  if (netaddr_from_string(&key->addr, addr)) {
    netaddr_invalidate(&key->addr);
    return -3;
  }
  if (netaddr_get_address_family(&key->addr) != AF_MAC48
      && netaddr_get_address_family(&key->addr) != AF_EUI64) {
    netaddr_invalidate(&key->addr);
    return -4;
  }
  return 0;
}

/**
 * Removes a layer-2 addr object from the database.
 * @param l2net layer-2 addr object
 */
static void
_net_remove(struct oonf_layer2_net *l2net) {
  struct oonf_layer2_neigh *l2neigh, *l2n_it;
  struct oonf_layer2_peer_address *l2peer, *l2peer_it;

  /* free all embedded neighbors */
  avl_for_each_element_safe(&l2net->neighbors, l2neigh, _node, l2n_it) {
    _neigh_remove(l2neigh);
  }

  /* free all attached peer addresses */
  avl_for_each_element_safe(&l2net->local_peer_ips, l2peer, _net_node, l2peer_it) {
    oonf_layer2_net_remove_ip(l2peer, l2peer->origin);
  }

  oonf_class_event(&_l2network_class, l2net, OONF_OBJECT_REMOVED);

  /* remove interface listener */
  os_interface_remove(&l2net->if_listener);

  /* free addr */
  avl_remove(&_oonf_layer2_net_tree, &l2net->_node);
  oonf_class_free(&_l2network_class, l2net);
}

/**
 * Removes a layer-2 neighbor object from the database
 * @param l2neigh layer-2 neighbor object
 */
static void
_neigh_remove(struct oonf_layer2_neigh *l2neigh) {
  struct oonf_layer2_destination *l2dst, *l2dst_it;
  struct oonf_layer2_neighbor_address *l2addr, *l2addr_it;

  /* free all embedded destinations */
  avl_for_each_element_safe(&l2neigh->destinations, l2dst, _node, l2dst_it) {
    oonf_layer2_destination_remove(l2dst);
  }

  /* free all attached neighbor addresses */
  avl_for_each_element_safe(&l2neigh->remote_neighbor_ips, l2addr, _neigh_node, l2addr_it) {
    oonf_layer2_neigh_remove_ip(l2addr, l2addr->origin);
  }

  /* inform user that mac entry will be removed */
  oonf_class_event(&_l2neighbor_class, l2neigh, OONF_OBJECT_REMOVED);

  /* free resources for mac entry */
  avl_remove(&l2neigh->network->neighbors, &l2neigh->_node);
  oonf_class_free(&_l2neighbor_class, l2neigh);
}
