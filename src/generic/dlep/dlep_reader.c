
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

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_reader.h>
#include <oonf/generic/dlep/dlep_session.h>

/**
 * Parse a heartbeat TLV
 * @param interval pointer to storage for heartbeat interval
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_HEARTBEAT_INTERVAL_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_heartbeat_tlv(uint64_t *interval, struct dlep_session *session, struct dlep_parser_value *value) {
  uint32_t tmp;
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_HEARTBEAT_INTERVAL_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  memcpy(&tmp, ptr, sizeof(tmp));
  *interval = ntohl(tmp);
  return 0;
}

/**
 * Parse a DLEP peer type TLV
 * @param text pointer to buffer for peer type
 * @param text_length length of buffer for peer type
 * @param secured_medium set to true if medium is secured, false otherwise
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_PEER_TYPE_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_peer_type(
  char *text, size_t text_length, bool *secured_medium, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_PEER_TYPE_TLV);
    if (!value) {
      return -1;
    }
  }
  if (value->length == 0) {
    return -1;
  }

  ptr = dlep_session_get_tlv_binary(session, value);

  *secured_medium = (ptr[0] & DLEP_PEER_TYPE_SECURED) != 0;

  if (value->length > 1 && text_length > 0) {
    /* generate a 0 terminated copy of the text */
    if (text_length - 1u > value->length - 1u) {
      memcpy(text, &ptr[1], value->length - 1u);
      text[value->length - 1u] = 0;
    }
    else {
      memcpy(text, &ptr[1], text_length - 2u);
      text[text_length - 2u] = 0;
    }
  }
  return 0;
}

/**
 * Parse a DLEP mac address TLV
 * @param key pointer to link-id storage
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_MAC_ADDRESS_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_mac_tlv(struct oonf_layer2_neigh_key *key, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_MAC_ADDRESS_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  return netaddr_from_binary(&key->addr, ptr, value->length, 0);
}

/**
 * Parse a DLEP link-id TLV
 * @param key pointer to link-id storage
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_LID_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_lid_tlv(struct oonf_layer2_neigh_key *key, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_LID_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  memcpy(key->link_id, ptr, value->length);
  key->link_id_length = value->length;
  return 0;
}

/**
 * Parse a DLEP link-id length TLV
 * @param length pointer to link-id length storage
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_LID_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_lid_length_tlv(uint16_t *length, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;
  uint16_t tmp16;
  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_LID_LENGTH_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  memcpy(&tmp16, ptr, sizeof(tmp16));
  *length = ntohs(tmp16);

  return 0;
}

/**
 * Parse DLEP IPv4 address TLV
 * @param ipv4 pointer to address storage
 * @param add pointer to boolean for flag storage
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPV4_ADDRESS_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv4_tlv(struct netaddr *ipv4, bool *add, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV4_ADDRESS_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  *add = (ptr[0] & DLEP_IP_ADD) == DLEP_IP_ADD;
  return netaddr_from_binary(ipv4, &ptr[1], 4, AF_INET);
}

/**
 * Parse DLEP IPv6 address TLV
 * @param ipv6 pointer to address storage
 * @param add pointer to boolean for flag storage
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPV6_ADDRESS_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv6_tlv(struct netaddr *ipv6, bool *add, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV6_ADDRESS_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  *add = (ptr[0] & DLEP_IP_ADD) == DLEP_IP_ADD;
  return netaddr_from_binary(ipv6, &ptr[1], 16, AF_INET6);
}

/**
 * Parse DLEP IPv4 subnet TLV
 * @param ipv4 pointer to address storage
 * @param add pointer to boolean for flag storage
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPV4_SUBNET_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv4_subnet_tlv(
  struct netaddr *ipv4, bool *add, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV4_SUBNET_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  *add = (ptr[0] & DLEP_IP_ADD) == DLEP_IP_ADD;
  return netaddr_from_binary_prefix(ipv4, &ptr[1], 4, AF_INET, ptr[5]);
}

/**
 * Parse DLEP IPv6 subnet TLV
 * @param ipv6 pointer to address storage
 * @param add pointer to boolean for flag storage
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPV6_SUBNET_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv6_subnet_tlv(
  struct netaddr *ipv6, bool *add, struct dlep_session *session, struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV6_SUBNET_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  *add = (ptr[0] & DLEP_IP_ADD) == DLEP_IP_ADD;
  return netaddr_from_binary_prefix(ipv6, &ptr[1], 16, AF_INET6, ptr[17]);
}

/**
 * Parse a DLEP IPv4 conpoint TLV
 * @param addr pointer to address storage
 * @param port pointer to port storage
 * @param tls pointer to storage for TLV flag
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPv4_CONPOINT_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv4_conpoint_tlv(
  struct netaddr *addr, uint16_t *port, bool *tls, struct dlep_session *session, struct dlep_parser_value *value) {
  uint16_t tmp;
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV4_CONPOINT_TLV);
    if (!value) {
      return -1;
    }
  }

  if (value->length != 5 && value->length != 7) {
    return -1;
  }

  ptr = dlep_session_get_tlv_binary(session, value);

  /* handle TLS flag */
  *tls = (ptr[0] & DLEP_CONNECTION_TLS) == DLEP_CONNECTION_TLS;

  /* handle port */
  if (value->length == 7) {
    memcpy(&tmp, &ptr[5], sizeof(tmp));
    *port = ntohs(tmp);
  }
  else {
    *port = DLEP_PORT;
  }

  /* handle IP */
  return netaddr_from_binary(addr, &ptr[1], 4, AF_INET);
}

/**
 * Parse a DLEP IPv6 conpoint TLV
 * @param addr pointer to address storage
 * @param port pointer to port storage
 * @param tls pointer to storage for TLV flag
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPv6_CONPOINT_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv6_conpoint_tlv(
  struct netaddr *addr, uint16_t *port, bool *tls, struct dlep_session *session, struct dlep_parser_value *value) {
  uint16_t tmp;
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV6_CONPOINT_TLV);
    if (!value) {
      return -1;
    }
  }

  if (value->length != 17 && value->length != 19) {
    return -1;
  }

  ptr = dlep_session_get_tlv_binary(session, value);

  /* handle TLS flag */
  *tls = (ptr[0] & DLEP_CONNECTION_TLS) == DLEP_CONNECTION_TLS;

  /* handle port */
  if (value->length == 19) {
    memcpy(&tmp, &ptr[17], sizeof(tmp));
    *port = ntohs(tmp);
  }
  else {
    *port = DLEP_PORT;
  }

  /* handle IP */
  return netaddr_from_binary(addr, &ptr[1], 16, AF_INET6);
}

/**
 * Parse a DLEP IPv4 DNS TLV
 * @param addr pointer to address storage
 * @param port pointer to port storage
 * @param tls pointer to storage for TLV flag
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPv4_DNS_SERVER_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv4_dns_tlv(
  union netaddr_socket *sock, struct dlep_session *session, struct dlep_parser_value *value) {
  struct netaddr addr;
  uint16_t tmp;
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV4_DNS_SERVER_TLV);
    if (!value) {
      return -1;
    }
  }

  if (value->length != 6) {
    return -1;
  }

  ptr = dlep_session_get_tlv_binary(session, value);

  /* handle port */
  memcpy(&tmp, &ptr[4], sizeof(tmp));
  tmp = ntohs(tmp);

  if (netaddr_from_binary(&addr, &ptr[0], 4, AF_INET)) {
    return -1;
  }

  return netaddr_socket_init(sock, &addr, tmp, session->l2_listener.data->_addr_initialized);
}

/**
 * Parse a DLEP IPv6 DNS TLV
 * @param addr pointer to address storage
 * @param port pointer to port storage
 * @param tls pointer to storage for TLV flag
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_IPv6_DNS_SERVER_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_ipv6_dns_tlv(
  union netaddr_socket *sock, struct dlep_session *session, struct dlep_parser_value *value) {
  struct netaddr addr;
  uint16_t tmp;
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_IPV6_DNS_SERVER_TLV);
    if (!value) {
      return -1;
    }
  }

  if (value->length != 18) {
    return -1;
  }

  ptr = dlep_session_get_tlv_binary(session, value);

  /* handle port */
  memcpy(&tmp, &ptr[16], sizeof(tmp));
  tmp = ntohs(tmp);

  if (netaddr_from_binary(&addr, &ptr[0], 4, AF_INET)) {
    return -1;
  }

  return netaddr_socket_init(sock, &addr, tmp, session->l2_listener.data->_addr_initialized);
}

/**
 * Parse a generic uint64 value TLV
 * @param number storage for uint64 value
 * @param tlv_id tlv_id to parse
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   tlv_id TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_uint64(uint64_t *number, uint16_t tlv_id, struct dlep_session *session, struct dlep_parser_value *value) {
  uint64_t tmp;
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, tlv_id);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  memcpy(&tmp, ptr, sizeof(tmp));
  *number = be64toh(tmp);
  return 0;
}

/**
 * Parse a generic int64 value TLV
 * @param number storage for int64 value
 * @param tlv_id tlv_id to parse
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   tlv_id TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_int64(int64_t *number, uint16_t tlv_id, struct dlep_session *session, struct dlep_parser_value *value) {
  uint64_t tmp;
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, tlv_id);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  memcpy(&tmp, ptr, sizeof(tmp));
  *number = (int64_t)(be64toh(tmp));
  return 0;
}

/**
 * Parse a DLEP status TLV
 * @param status pointer to store status
 * @param text pointer to store text status
 * @param text_length length of text status buffer
 * @param session dlep session
 * @param value dlep value to parse, NULL for using the first
 *   DLEP_STATUS_TLV value
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_status(enum dlep_status *status, char *text, size_t text_length, struct dlep_session *session,
  struct dlep_parser_value *value) {
  const uint8_t *ptr;

  if (!value) {
    value = dlep_session_get_tlv_value(session, DLEP_STATUS_TLV);
    if (!value) {
      return -1;
    }
  }

  ptr = dlep_session_get_tlv_binary(session, value);
  *status = ptr[0];

  if (value->length > 1 && text_length > 0) {
    /* generate a 0 terminated copy of the text */
    if (text_length >= value->length) {
      memcpy(text, &ptr[1], value->length - 1);
      text[value->length - 1] = 0;
    }
    else {
      memcpy(text, &ptr[1], text_length - 1);
      text[text_length - 1] = 0;
    }
  }
  else if (text_length) {
    *text = 0;
  }
  return 0;
}

/**
 * Parse a metric TLV and copy it into a layer2 data object
 * @param data pointer to layer2 data object
 * @param meta metadata description for data
 * @param session dlep session
 * @param dlep_tlv DLEP TLV id
 * @param scaling fixed integer arithmetics scaling factor
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_reader_map_identity(struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling) {
  struct dlep_parser_value *value;
  int64_t l2value;
  uint64_t tmp64;
  uint32_t tmp32;
  uint16_t tmp16;
  uint8_t tmp8;
  const uint8_t *dlepvalue;
  struct netaddr addr;
  union netaddr_socket sock;

  value = dlep_session_get_tlv_value(session, dlep_tlv);
  if (!value) {
    return 0;
  }

  dlepvalue = dlep_parser_get_tlv_binary(&session->parser, value);
  l2value = 0;

  if (meta->type == OONF_LAYER2_INTEGER_DATA || meta->type == OONF_LAYER2_BOOLEAN_DATA) {
    switch (value->length) {
      case 8:
        memcpy(&tmp64, dlepvalue, 8);
        l2value = (int64_t)be64toh(tmp64);
        break;
      case 4:
        memcpy(&tmp32, dlepvalue, 4);
        l2value = (int32_t)ntohl(tmp32);
        break;
      case 2:
        memcpy(&tmp16, dlepvalue, 2);
        l2value = (int16_t)ntohs(tmp16);
        break;
      case 1:
        memcpy(&tmp8, dlepvalue, 1);
        l2value = (int8_t)tmp8;
        break;
      default:
        return -1;
    }
  }

  switch (meta->type) {
    case OONF_LAYER2_INTEGER_DATA:
      oonf_layer2_data_set_int64(data, session->l2_origin, meta, l2value, scaling);
      break;
    case OONF_LAYER2_BOOLEAN_DATA:
      oonf_layer2_data_set_bool(data, session->l2_origin, meta, l2value != 0);
      break;
    case OONF_LAYER2_NETWORK_DATA:
      netaddr_from_binary(&addr, dlepvalue, value->length, 0);
      oonf_layer2_data_set_netaddr(data, session->l2_origin, meta, &addr);
      break;
    case OONF_LAYER2_SOCKET_DATA:
      netaddr_socket_invalidate(&sock);
      if (value->length == 6 || value->length == 18) {
        netaddr_from_binary(&addr, dlepvalue, value->length-2, 0);
        memcpy(&tmp16, &dlepvalue[value->length-2], 2);

        netaddr_socket_init(&sock, &addr, ntohs(tmp16), session->l2_listener.data->index);
      }
      oonf_layer2_data_set_socket(data, session->l2_origin, meta, &sock);
      break;
    default:
      return -1;
  }
  return 0;
}

/**
 * Automatically map all predefined metric values of an
 * extension for layer2 neighbor data from DLEP TLVs to
 * the layer2 database
 * @param data layer2 neighbor data array
 * @param session dlep session
 * @param ext dlep extension
 * @return 0 if everything worked fine, negative index
 *   (minus 1) of the conversion that failed.
 */
int
dlep_reader_map_l2neigh_data(struct oonf_layer2_data *data, struct dlep_session *session,
    struct dlep_extension *ext) {
  struct dlep_neighbor_mapping *map;
  enum oonf_layer2_neighbor_index l2neigh_idx;

  size_t i;

  for (i = 0; i < ext->neigh_mapping_count; i++) {
    map = &ext->neigh_mapping[i];

    l2neigh_idx = map->layer2_dst;
    if (l2neigh_idx == 0) {
      l2neigh_idx = map->layer2;
    }
    if (map->from_tlv(&data[l2neigh_idx], oonf_layer2_neigh_metadata_get(l2neigh_idx), session,
        map->dlep, map->scaling)) {
      return -(i + 1);
    }
  }
  return 0;
}

/**
 * Automatically map all predefined metric values of an
 * extension for layer2 network data from DLEP TLVs to
 * the layer2 database
 * @param data layer2 network data array
 * @param session dlep session
 * @param ext dlep extension
 * @return 0 if everything worked fine, negative index
 *   (minus 1) of the conversion that failed.
 */
int
dlep_reader_map_l2net_data(struct oonf_layer2_data *data, struct dlep_session *session, struct dlep_extension *ext) {
  struct dlep_network_mapping *map;
  enum oonf_layer2_network_index l2net_idx;
  size_t i;

  for (i = 0; i < ext->if_mapping_count; i++) {
    map = &ext->if_mapping[i];

    l2net_idx = map->layer2_dst;
    if (l2net_idx == 0) {
      l2net_idx = map->layer2;
    }
    if (map->from_tlv(&data[l2net_idx], oonf_layer2_net_metadata_get(l2net_idx), session,
        map->dlep, map->scaling)) {
      return -(i + 1);
    }
  }
  return 0;
}
