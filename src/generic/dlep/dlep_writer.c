
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

#include <arpa/inet.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>

#include <oonf/libcore/oonf_logging.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_writer.h>

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <endian.h> /* htobe64 */

/**
 * Start to write a new DLEP signal/message into a buffer
 * @param writer dlep writer
 * @param signal_type signal/message type
 */
void
dlep_writer_start_signal(struct dlep_writer *writer, uint16_t signal_type) {
  writer->signal_type = signal_type;
  writer->signal_start = abuf_getlen(writer->out);

  abuf_append_uint16(writer->out, htons(signal_type));
  abuf_append_uint16(writer->out, 0);
}

/**
 * Add a TLV to a DLEP writer buffer
 * @param writer dlep writer
 * @param type TLV type
 * @param data pointer to TLV value
 * @param len length of value, can be 0
 */
void
dlep_writer_add_tlv(struct dlep_writer *writer, uint16_t type, const void *data, uint16_t len) {
  abuf_append_uint16(writer->out, htons(type));
  abuf_append_uint16(writer->out, htons(len));
  abuf_memcpy(writer->out, data, len);
}

/**
 * Add a TLV to a DLEP writer buffer
 * @param writer dlep writer
 * @param type TLV type
 * @param data1 first part of TLV value
 * @param len1 length of first value
 * @param data2 second part of TLV value
 * @param len2 length of second value
 */
void
dlep_writer_add_tlv2(
  struct dlep_writer *writer, uint16_t type, const void *data1, uint16_t len1, const void *data2, uint16_t len2) {
  abuf_append_uint16(writer->out, htons(type));
  abuf_append_uint16(writer->out, htons(len1 + len2));
  abuf_memcpy(writer->out, data1, len1);
  abuf_memcpy(writer->out, data2, len2);
}

/**
 * Finish a DLEP signal/message
 * @param writer dlep writer
 * @param source logging source for error messages
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_writer_finish_signal(struct dlep_writer *writer, enum oonf_log_source source) {
  size_t length;
  uint16_t tmp16;
  char *dst;

  if (abuf_has_failed(writer->out)) {
    OONF_WARN(source, "Could not build signal: %u", writer->signal_type);
    return -1;
  }

  length = abuf_getlen(writer->out) - writer->signal_start;
  if (length > 65535 + 4) {
    OONF_WARN(
      source, "Signal %u became too long: %" PRINTF_SIZE_T_SPECIFIER, writer->signal_type, abuf_getlen(writer->out));
    return -1;
  }

  /* calculate network ordered size */
  tmp16 = htons(length - 4);

  /* put it into the signal */
  dst = abuf_getptr(writer->out);
  memcpy(&dst[writer->signal_start + 2], &tmp16, sizeof(tmp16));

  OONF_DEBUG_HEX(source, &dst[writer->signal_start], length, "Finished signal %u:", writer->signal_type);
  return 0;
}

/**
 * Write a DLEP heartbeat TLV
 * @param writer dlep writer
 * @param interval interval length in milliseconds
 */
void
dlep_writer_add_heartbeat_tlv(struct dlep_writer *writer, uint64_t interval) {
  uint32_t value;

  value = htonl(interval);

  dlep_writer_add_tlv(writer, DLEP_HEARTBEAT_INTERVAL_TLV, &value, sizeof(value));
}

/**
 * Write a DLEP peer type TLV
 * @param writer dlep writer
 * @param peer_type ZERO terminated peer type
 * @param access_control true if radio implements access control, false otherwise
 */
void
dlep_writer_add_peer_type_tlv(struct dlep_writer *writer, const char *peer_type, bool access_control) {
  char flags;

  flags = access_control ? DLEP_PEER_TYPE_SECURED : DLEP_PEER_TYPE_OPEN;

  dlep_writer_add_tlv2(writer, DLEP_PEER_TYPE_TLV, &flags, sizeof(flags), peer_type, strlen(peer_type));
}

/**
 * Write a DLEP MAC address TLV
 * @param writer dlep writer
 * @param mac_lid mac address/LID
 * @return -1 if address was wrong type, 0 otherwise
 */
int
dlep_writer_add_mac_tlv(struct dlep_writer *writer, const struct oonf_layer2_neigh_key *mac_lid) {
  uint8_t value[8];

  switch (netaddr_get_address_family(&mac_lid->addr)) {
    case AF_MAC48:
    case AF_EUI64:
      break;
    default:
      return -1;
  }

  netaddr_to_binary(value, &mac_lid->addr, 8);

  dlep_writer_add_tlv(writer, DLEP_MAC_ADDRESS_TLV, value, netaddr_get_binlength(&mac_lid->addr));
  return 0;
}

/**
 * Write a DLEP Link-ID TLV if length is greater than zero
 * @param writer dlep writer
 * @param mac_lid mac address/LID
 * @return -1 if address was wrong type, 0 otherwise
 */
int
dlep_writer_add_lid_tlv(struct dlep_writer *writer, const struct oonf_layer2_neigh_key *mac_lid) {
  if (mac_lid->link_id_length > 0) {
    dlep_writer_add_tlv(writer, DLEP_LID_TLV, mac_lid->link_id, mac_lid->link_id_length);
  }
  return 0;
}

/**
 * Write a DLEP Link-ID length TLV
 * @param writer dlep writer
 * @param link_id_length length of link-id
 * @return -1 if address was wrong type, 0 otherwise
 */
int
dlep_writer_add_lid_length_tlv(struct dlep_writer *writer, uint16_t link_id_length) {
  uint16_t value;

  value = htons(link_id_length);
  dlep_writer_add_tlv(writer, DLEP_LID_LENGTH_TLV, &value, sizeof(value));
  return 0;
}

/**
 * Write a DLEP IPv4/IPv6 address/subnet TLV
 * @param writer dlep writer
 * @param ip IPv4 address
 * @param add true if address should be added, false to remove it
 */
int
dlep_writer_add_ip_tlv(struct dlep_writer *writer, const struct netaddr *ip, bool add) {
  uint8_t value[18];

  value[0] = add ? DLEP_IP_ADD : DLEP_IP_REMOVE;
  netaddr_to_binary(&value[1], ip, 16);

  switch (netaddr_get_address_family(ip)) {
    case AF_INET:
      value[5] = netaddr_get_prefix_length(ip);
      if (value[5] != 32) {
        dlep_writer_add_tlv(writer, DLEP_IPV4_SUBNET_TLV, value, 6);
      }
      else {
        dlep_writer_add_tlv(writer, DLEP_IPV4_ADDRESS_TLV, value, 5);
      }
      break;
    case AF_INET6:
      value[17] = netaddr_get_prefix_length(ip);
      if (value[17] != 128) {
        dlep_writer_add_tlv(writer, DLEP_IPV6_SUBNET_TLV, value, 18);
      }
      else {
        dlep_writer_add_tlv(writer, DLEP_IPV6_ADDRESS_TLV, value, 17);
      }
      break;
    default:
      return -1;
  }
  return 0;
}

/**
 * Write a DLEP IPv4 conpoint TLV
 * @param writer dlep writer
 * @param addr IPv4 address
 * @param port port number
 * @param tls TLS capability flag
 */
void
dlep_writer_add_ipv4_conpoint_tlv(struct dlep_writer *writer, const struct netaddr *addr, uint16_t port, bool tls) {
  uint8_t value[7];

  if (netaddr_get_address_family(addr) != AF_INET) {
    return;
  }

  /* convert port to network byte order */
  port = htons(port);

  /* copy data into value buffer */
  value[0] = tls ? DLEP_CONNECTION_TLS : DLEP_CONNECTION_PLAIN;
  netaddr_to_binary(&value[1], addr, sizeof(value));
  memcpy(&value[5], &port, sizeof(port));

  dlep_writer_add_tlv(writer, DLEP_IPV4_CONPOINT_TLV, &value, sizeof(value));
}

/**
 * Write a DLEP IPv6 conpoint TLV
 * @param writer dlep writer
 * @param addr IPv6 address
 * @param port port number
 * @param tls TLS capability flag
 */
void
dlep_writer_add_ipv6_conpoint_tlv(struct dlep_writer *writer, const struct netaddr *addr, uint16_t port, bool tls) {
  uint8_t value[19];

  if (netaddr_get_address_family(addr) != AF_INET6) {
    return;
  }

  /* convert port to network byte order */
  port = htons(port);

  /* copy data into value buffer */
  value[0] = tls ? DLEP_CONNECTION_TLS : DLEP_CONNECTION_PLAIN;
  netaddr_to_binary(&value[1], addr, sizeof(value));
  memcpy(&value[17], &port, sizeof(port));

  dlep_writer_add_tlv(writer, DLEP_IPV6_CONPOINT_TLV, &value, sizeof(value));
}

/**
 * Write a DLEP IPv4 conpoint TLV
 * @param writer dlep writer
 * @param addr IPv4 address
 * @param port port number
 */
void
dlep_writer_add_ipv4_dns_tlv(struct dlep_writer *writer, const union netaddr_socket *sock) {
  struct netaddr ip;
  uint16_t port;
  uint8_t value[6];

  netaddr_from_socket(&ip, sock);
  port = netaddr_socket_get_port(sock);

  if (netaddr_get_address_family(&ip) != AF_INET) {
    return;
  }

  /* convert port to network byte order */
  port = htons(port);

  /* copy data into value buffer */
  netaddr_to_binary(&value[0], &ip, sizeof(value));
  memcpy(&value[4], &port, sizeof(port));

  dlep_writer_add_tlv(writer, DLEP_IPV4_DNS_SERVER_TLV, &value, sizeof(value));
}

/**
 * Write a DLEP IPv6 conpoint TLV
 * @param writer dlep writer
 * @param addr IPv6 address
 * @param port port number
 */
void
dlep_writer_add_ipv6_dns_tlv(struct dlep_writer *writer, const union netaddr_socket *sock) {
  struct netaddr ip;
  uint16_t port;
  uint8_t value[18];

  netaddr_from_socket(&ip, sock);
  port = netaddr_socket_get_port(sock);

  if (netaddr_get_address_family(&ip) != AF_INET6) {
    return;
  }

  /* convert port to network byte order */
  port = htons(port);

  /* copy data into value buffer */
  netaddr_to_binary(&value[0], &ip, sizeof(value));
  memcpy(&value[16], &port, sizeof(port));

  dlep_writer_add_tlv(writer, DLEP_IPV6_DNS_SERVER_TLV, &value, sizeof(value));
}

/**
 * Add a DLEP tlv with uint64 value
 * @param writer dlep writer
 * @param number value
 * @param tlv tlv id
 */
void
dlep_writer_add_uint64(struct dlep_writer *writer, uint64_t number, enum dlep_tlvs tlv) {
  uint64_t value;

  value = be64toh(number);

  dlep_writer_add_tlv(writer, tlv, &value, sizeof(value));
}

/**
 * Add a DLEP tlv with int64 value
 * @param writer dlep writer
 * @param number value
 * @param tlv tlv id
 */
void
dlep_writer_add_int64(struct dlep_writer *writer, int64_t number, enum dlep_tlvs tlv) {
  uint64_t *value = (uint64_t *)(&number);

  *value = htonl(*value);

  dlep_writer_add_tlv(writer, tlv, value, sizeof(*value));
}

/**
 * Write a DLEP status TLV
 * @param writer dlep writer
 * @param status dlep status code
 * @param text ZERO terminated DLEP status text
 * @return -1 if status text was too long, 0 otherwise
 */
int
dlep_writer_add_status(struct dlep_writer *writer, enum dlep_status status, const char *text) {
  uint8_t value;
  size_t txtlen;

  value = status;
  txtlen = strlen(text);
  if (txtlen > 65534) {
    return -1;
  }

  dlep_writer_add_tlv2(writer, DLEP_STATUS_TLV, &value, sizeof(value), text, txtlen);
  return 0;
}

/**
 * Write the supported DLEP extensions TLV
 * @param writer dlep writer
 * @param extensions array of supported extensions
 * @param ext_count number of supported extensions
 */
void
dlep_writer_add_supported_extensions(struct dlep_writer *writer, const uint16_t *extensions, uint16_t ext_count) {
  dlep_writer_add_tlv(writer, DLEP_EXTENSIONS_SUPPORTED_TLV, extensions, ext_count * 2);
}

/**
 * Write a layer2 number object into a DLEP TLV
 * @param writer dlep writer
 * @param data layer2 data
 * @param tlv tlv id
 * @param length tlv value length (1,2,4 or 8 bytes)
 * @return -1 if an error happened, 0 otherwise
 */
static int
_map_number(struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling) {
  int64_t l2value64;
  uint64_t tmp64;
  uint32_t tmp32;
  uint16_t tmp16;
  uint8_t tmp8;
  void *value;

  if (meta->type == OONF_LAYER2_INTEGER_DATA) {
    l2value64 = oonf_layer2_data_get_int64(data, scaling, 0);
  }
  else {
    l2value64 = oonf_layer2_data_get_boolean(data, false) ? 1 : 0;
  }

  switch (length) {
    case 8:
      tmp64 = htobe64((uint64_t)l2value64);
      value = &tmp64;
      break;
    case 4:
      tmp32 = htonl((uint32_t)((int32_t)l2value64));
      value = &tmp32;
      break;
    case 2:
      tmp16 = htons((uint16_t)((int16_t)l2value64));
      value = &tmp16;
      break;
    case 1:
      tmp8 = (uint8_t)((int8_t)l2value64);
      value = &tmp8;
      break;
    default:
      return -1;
  }

  dlep_writer_add_tlv(writer, tlv, value, length);
  return 0;
}

/**
 * Write a layer2 network object into a DLEP TLV
 * @param writer dlep writer
 * @param data layer2 data
 * @param tlv tlv id
 * @param length tlv value length (4, 6, 16 or 18 bytes)
 * @return -1 if an error happened, 0 otherwise
 */
static int
_map_network(struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length) {
  const union netaddr_socket *sock;
  const struct netaddr *addr;
  const uint8_t *addr_bin;
  uint8_t buffer[18];
  uint16_t port;
  size_t addr_len;

  /* extract address (and port for sockets) */
  if (meta->type == OONF_LAYER2_NETWORK_DATA) {
    addr = oonf_layer2_data_get_netaddr(data);
    addr_bin = netaddr_get_binptr(addr);
    addr_len = netaddr_get_binlength(addr);
  }
  else {
    sock = oonf_layer2_data_get_socket(data);
    addr_bin = netaddr_socket_get_addr_binptr(sock);
    addr_len = netaddr_socket_get_addr_binlength(sock);
    port = netaddr_socket_get_port(sock);
  }

  if (addr_len == 0) {
    /* unspecified address, don't produce TLV */
    return 0;
  }

  /* check address length */
  if (addr_len + (meta->type == OONF_LAYER2_SOCKET_DATA ? 2 : 0) != length) {
    return -1;
  }

  memcpy(buffer, addr_bin, addr_len);
  if (meta->type == OONF_LAYER2_SOCKET_DATA) {
    port = htons(port);
    memcpy(&buffer[addr_len], &port, sizeof(port));
  }

  dlep_writer_add_tlv(writer, tlv, buffer, length);
  return 0;
}

/**
 * Write a layer2 data object into a DLEP TLV
 * @param writer dlep writer
 * @param data layer2 data
 * @param tlv tlv id
 * @param length tlv value length (1,2,4 or 8 bytes)
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_writer_map_identity(struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling) {
  if (!oonf_layer2_data_has_value(data)) {
    /* no data available */
    return 0;
  }
  if (meta->type != oonf_layer2_data_get_type(data)) {
    /* bad data type */
    return -1;
  }

  if (meta->type == OONF_LAYER2_INTEGER_DATA || meta->type == OONF_LAYER2_BOOLEAN_DATA) {
    return _map_number(writer, data, meta, tlv, length, scaling);
  }
  if (meta->type == OONF_LAYER2_NETWORK_DATA || meta->type == OONF_LAYER2_SOCKET_DATA) {
    return _map_network(writer, data, meta, tlv, length);
  }
  return -1;
}

/**
 * Automatically map all predefined metric values of an
 * extension for layer2 neighbor data from the layer2
 * database to DLEP TLVs
 * @param writer dlep writer
 * @param ext dlep extension
 * @param data layer2 neighbor data array
 * @param def layer2 neighbor defaults data array
 * @return 0 if everything worked fine, negative index
 *   (minus 1) of the conversion that failed.
 */
int
dlep_writer_map_l2neigh_data(
  struct dlep_writer *writer, struct dlep_extension *ext, struct oonf_layer2_data *data, struct oonf_layer2_data *def) {
  struct dlep_neighbor_mapping *map;
  struct oonf_layer2_data *ptr;
  size_t i;

  for (i = 0; i < ext->neigh_mapping_count; i++) {
    map = &ext->neigh_mapping[i];

    ptr = &data[map->layer2];
    if (!oonf_layer2_data_has_value(ptr) && def) {
      ptr = &def[map->layer2];
    }

    if (map->to_tlv(writer, ptr, oonf_layer2_neigh_metadata_get(map->layer2),
        map->dlep, map->length, map->scaling)) {
      return -(i + 1);
    }
  }
  return 0;
}

/**
 * Automatically map all predefined metric values of an
 * extension for layer2 network data from the layer2
 * database to DLEP TLVs
 * @param writer dlep writer
 * @param ext dlep extension
 * @param data layer2 network data array
 * @return 0 if everything worked fine, negative index
 *   (minus 1) of the conversion that failed.
 */
int
dlep_writer_map_l2net_data(struct dlep_writer *writer, struct dlep_extension *ext, struct oonf_layer2_data *data) {
  enum oonf_layer2_network_index l2net_idx;
  struct dlep_network_mapping *map;
  size_t i;

  for (i = 0; i < ext->if_mapping_count; i++) {
    map = &ext->if_mapping[i];

    l2net_idx = map->layer2_dst;
    if (l2net_idx == 0) {
      l2net_idx = map->layer2;
    }
    if (map->to_tlv(writer, &data[map->layer2], oonf_layer2_net_metadata_get(l2net_idx),
        map->dlep, map->length, map->scaling)) {
      return -(i + 1);
    }
  }
  return 0;
}
