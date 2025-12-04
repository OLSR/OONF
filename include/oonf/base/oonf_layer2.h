
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

#ifndef OONF_LAYER2_H_
#define OONF_LAYER2_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/os_interface.h>

/*! subsystem identifier */
#define OONF_LAYER2_SUBSYSTEM "layer2"

/*! memory class for layer2 neighbor */
#define LAYER2_CLASS_NEIGHBOR "layer2_neighbor"

/*! memory class for layer2 network */
#define LAYER2_CLASS_NETWORK "layer2_network"

/*! memory class for layer2 destination */
#define LAYER2_CLASS_DESTINATION "layer2_destination"

/*! memory class for layer2 network address */
#define LAYER2_CLASS_NETWORK_ADDRESS "layer2_network_address"

/*! memory class for layer2 neighbor address */
#define LAYER2_CLASS_NEIGHBOR_ADDRESS "layer2_neighbor_address"

/*! memory class for layer2 tracking of next link-id per neighbor */
#define LAYER2_CLASS_LID "layer2_lid"

enum {
  /*! maximum length of link id for layer2 neighbors */
  OONF_LAYER2_MAX_LINK_ID = 16,
};

/* configuration Macros for Layer2 keys */

/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the layer2 interface keys
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_LAYER2_NET_DATA_KEY(p_name, p_def, p_help, args...)                                                    \
  CFG_VALIDATE_CHOICE_CB_ARG(p_name, p_def, p_help, oonf_layer2_cfg_get_l2net_key, OONF_LAYER2_NET_COUNT, NULL, ##args)

/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the layer2 neighbor keys
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_LAYER2_NEIGH_DATA_KEY(p_name, p_def, p_help, args...)                                                  \
  CFG_VALIDATE_CHOICE_CB_ARG(                                                                                               \
    p_name, p_def, p_help, oonf_layer2_cfg_get_l2neigh_key, OONF_LAYER2_NEIGH_COUNT, NULL, ##args)

/**
 * Creates a cfg_schema_entry for a parameter that is a MAC address with optional
 * link id string
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_LAYER2_NEIGH_MAC_LID(p_name, p_def, p_help, args...)                                                  \
  _CFG_VALIDATE(p_name, p_def, p_help, .cb_validate = oonf_layer2_validate_mac_lid,                                        \
    .cb_valhelp = oonf_layer2_help_mac_lid, ##args)

/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the layer2 data comparators
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_VALIDATE_LAYER2_COMP(p_name, p_def, p_help, args...)                                                       \
  CFG_VALIDATE_CHOICE_CB_ARG(                                                                                          \
    p_name, p_def, p_help, oonf_layer2_cfg_get_l2comp, OONF_LAYER2_DATA_CMP_COUNT, NULL, ##args)


/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the layer2 interface keys
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_MAP_CHOICE_L2NET_DATA_KEY(p_reference, p_field, p_name, p_def, p_help, args...)                            \
  CFG_MAP_CHOICE_CB_ARG(                                                                                               \
    p_reference, p_field, p_name, p_def, p_help, oonf_layer2_cfg_get_l2net_key, OONF_LAYER2_NET_COUNT, NULL, ##args)

/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the layer2 interface keys
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_MAP_CHOICE_L2NEIGH_DATA_KEY(p_reference, p_field, p_name, p_def, p_help, args...)                          \
  CFG_MAP_CHOICE_CB_ARG(p_reference, p_field, p_name, p_def, p_help, oonf_layer2_cfg_get_l2neigh_key,                  \
    OONF_LAYER2_NEIGH_COUNT, NULL, ##args)

/**
 * Creates a cfg_schema_entry for a parameter that can be choosen
 * from the layer2 data comparators
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_MAP_CHOICE_L2COMP(p_reference, p_field, p_name, p_def, p_help, args...)                                    \
  CFG_MAP_CHOICE_CB_ARG(                                                                                               \
    p_reference, p_field, p_name, p_def, p_help, oonf_layer2_cfg_get_l2comp, OONF_LAYER2_DATA_CMP_COUNT, NULL, ##args)

/**
 * Creates a cfg_schema_entry for a parameter that is a MAC address with optional
 * link id string
 * @param p_name parameter name
 * @param p_def parameter default value
 * @param p_help help text for configuration entry
 * @param args variable list of additional arguments
 */
#define CFG_MAP_LAYER2_NEIGH_MAC_LID(p_reference, p_field, p_name, p_def, p_help, args...)                            \
  CFG_VALIDATE_LAYER2_NEIGH_MAC_LID(p_name, p_def, p_help, .cb_to_binary = oonf_layer2_tobin_mac_lid,                 \
    .bin_size = calculate_size(p_reference, p_field), .bin_offset = offsetof(struct p_reference, p_field), ##args)


/**
 * priorities of layer2 originators
 */
enum oonf_layer2_origin_priority
{
  OONF_LAYER2_ORIGIN_UNKNOWN = 0,
  OONF_LAYER2_ORIGIN_DEFAULT = 10,
  OONF_LAYER2_ORIGIN_UNRELIABLE = 20,
  OONF_LAYER2_ORIGIN_CONFIGURED = 30,
  OONF_LAYER2_ORIGIN_RELIABLE = 40,
  OONF_LAYER2_ORIGIN_OVERWRITE = 50,
};

/**
 * Origin for layer2 data
 */
struct oonf_layer2_origin {
  const char *name;

  /*! true if data will be constantly updated by a plugin */
  bool proactive;

  /*! priority of this originator */
  enum oonf_layer2_origin_priority priority;

  /*! true if this originator creates l2neighbor LID entries */
  bool lid;

  /* index number of the originator for LID creation */
  uint32_t lid_index;

  /*! node for tree of originators */
  struct avl_node _node;
};

enum oonf_layer2_data_type
{
  OONF_LAYER2_INTEGER_DATA,
  OONF_LAYER2_BOOLEAN_DATA,
  OONF_LAYER2_NETWORK_DATA,
  OONF_LAYER2_SOCKET_DATA,

  OONF_LAYER2_DATA_TYPE_COUNT,
};

union oonf_layer2_value {
  int64_t integer;
  bool boolean;
  struct netaddr addr;
  union netaddr_socket socket;
};

/**
 * Metadata flags for network and socket data type
 */
enum oonf_layer2_network_flags {
  /*! IPv4 prefix/socket is allowed */
  OONF_LAYER2_IPV4_DATA = 1<<0,

  /*! IPv6 prefix/socket is allowed */
  OONF_LAYER2_IPV6_DATA = 1<<1,

  /*! unspecified prefix/socket is allowed */
  OONF_LAYER2_UNSPEC_DATA = 1<<2,

  /*! Only hosts are allowed, no prefixes */
  OONF_LAYER2_HOST_ONLY_DATA = 1<<3,
};

/**
 * Metadata of layer2 data entry for automatic processing
 */
struct oonf_layer2_metadata {
  /*! type of data */
  const char key[17];

  /*! data type */
  enum oonf_layer2_data_type type;

  /*! unit (bit/s, byte, ...) */
  const char unit[8];

  /*! scaling factor for  */
  const uint64_t scaling;

  /*! flags for network and socket datatype */
  enum oonf_layer2_network_flags net_flags;
};

/**
 * Single data entry of layer2 network or neighbor
 */
struct oonf_layer2_data {
  /*! data value */
  union oonf_layer2_value _value;

  /*! metadata corresponding to this data */
  const struct oonf_layer2_metadata *_meta;

  /*! layer2 originator id */
  const struct oonf_layer2_origin *_origin;
};

/**
 * Comparator options for layer2 data
 */
enum oonf_layer2_data_comparator_type
{
  OONF_LAYER2_DATA_CMP_EQUALS,
  OONF_LAYER2_DATA_CMP_NOT_EQUALS,
  OONF_LAYER2_DATA_CMP_LESSER,
  OONF_LAYER2_DATA_CMP_LESSER_OR_EQUALS,
  OONF_LAYER2_DATA_CMP_GREATER,
  OONF_LAYER2_DATA_CMP_GREATER_OR_EQUALS,

  OONF_LAYER2_DATA_CMP_COUNT,

  OONF_LAYER2_DATA_CMP_ILLEGAL = -1,
};

/**
 * list of layer2 network metrics
 */
enum oonf_layer2_network_index
{
  /*! primary center frequency */
  OONF_LAYER2_NET_FREQUENCY_1,

  /*! optional secondary center frequency */
  OONF_LAYER2_NET_FREQUENCY_2,

  /*! primary bandwidth */
  OONF_LAYER2_NET_BANDWIDTH_1,

  /*! optional secondary bandwidth */
  OONF_LAYER2_NET_BANDWIDTH_2,

  /*! noise level in dBm */
  OONF_LAYER2_NET_NOISE,

  /*! total time in ns the channel was active */
  OONF_LAYER2_NET_CHANNEL_ACTIVE,

  /*! total time in ns the channel was busy */
  OONF_LAYER2_NET_CHANNEL_BUSY,

  /*! total time in ns the channel was receiving */
  OONF_LAYER2_NET_CHANNEL_RX,

  /*! total time in ns the channel was transmitting */
  OONF_LAYER2_NET_CHANNEL_TX,

  /*! outgoing broadcast bitrate in bit/s */
  OONF_LAYER2_NET_TX_BC_BITRATE,

  /*! maixmum size of an ethernet/IP packet the router is allowed to send */
  OONF_LAYER2_NET_MTU,

  /*! true if unicast traffic is necessary for ratecontrol */
  OONF_LAYER2_NET_MCS_BY_PROBING,

  /*! true if interface does not support incoming broadcast/multicast */
  OONF_LAYER2_NET_RX_ONLY_UNICAST,

  /*! true if interface does not support incoming broadcast/multicast */
  OONF_LAYER2_NET_TX_ONLY_UNICAST,

  /*! true if radio provides multihop forwarding transparently */
  OONF_LAYER2_NET_RADIO_MULTIHOP,

  /*!
   * true if first frequency is uplink, second is downlink.
   * false if reported frequencies can be used for both reception/transmission
   */
  OONF_LAYER2_NET_BAND_UP_DOWN,

  /*! known local IPv4 DNS server */
  OONF_LAYER2_NET_IPV4_LOCAL_DNS,

  /*! known local IPv6 DNS server */
  OONF_LAYER2_NET_IPV6_LOCAL_DNS,

  /*! known remote IPv4 DNS server */
  OONF_LAYER2_NET_IPV4_REMOTE_DNS,

  /*! known remote IPv6 DNS server */
  OONF_LAYER2_NET_IPV6_REMOTE_DNS,

  /*! number of layer2 network metrics */
  OONF_LAYER2_NET_COUNT,
};

/**
 * list with types of layer2 networks
 */
enum oonf_layer2_network_type
{
  OONF_LAYER2_TYPE_UNDEFINED,
  OONF_LAYER2_TYPE_WIRELESS,
  OONF_LAYER2_TYPE_ETHERNET,
  OONF_LAYER2_TYPE_TUNNEL,

  OONF_LAYER2_TYPE_COUNT,
};

/**
 * list of layer2 neighbor metrics
 */
enum oonf_layer2_neighbor_index
{
  /*! outgoing signal in milli dBm */
  OONF_LAYER2_NEIGH_TX_SIGNAL,

  /*! incoming signal in milli dBm */
  OONF_LAYER2_NEIGH_RX_SIGNAL,

  /*! outgoing signal in milli dB */
  OONF_LAYER2_NEIGH_TX_SNR,

  /*! incoming signal in milli dB */
  OONF_LAYER2_NEIGH_RX_SNR,

  /*! outgoing bitrate in bit/s */
  OONF_LAYER2_NEIGH_TX_BITRATE,

  /*! incoming bitrate in bit/s */
  OONF_LAYER2_NEIGH_RX_BITRATE,

  /*! maximum possible outgoing bitrate in bit/s */
  OONF_LAYER2_NEIGH_TX_MAX_BITRATE,

  /*! maximum possible incoming bitrate in bit/s */
  OONF_LAYER2_NEIGH_RX_MAX_BITRATE,

  /*! total number of transmitted bytes */
  OONF_LAYER2_NEIGH_TX_BYTES,

  /*! total number of received bytes */
  OONF_LAYER2_NEIGH_RX_BYTES,

  /*! total number of transmitted frames */
  OONF_LAYER2_NEIGH_TX_FRAMES,

  /*! total number of received frames */
  OONF_LAYER2_NEIGH_RX_FRAMES,

  /*! average outgoing throughput in bit/s */
  OONF_LAYER2_NEIGH_RX_THROUGHPUT,

  /*! average incoming throughput in bit/s */
  OONF_LAYER2_NEIGH_TX_THROUGHPUT,

  /*! total number of frame retransmission of other radio*/
  OONF_LAYER2_NEIGH_RX_RETRIES,

  /*! total number of frame retransmission */
  OONF_LAYER2_NEIGH_TX_RETRIES,

  /*! total number of failed frame receptions */
  OONF_LAYER2_NEIGH_RX_FAILED,

  /*! total number of failed frame transmissions */
  OONF_LAYER2_NEIGH_TX_FAILED,

  /*! relative transmission link quality (0-100) */
  OONF_LAYER2_NEIGH_TX_RLQ,

  /*! relative receiver link quality (0-100) */
  OONF_LAYER2_NEIGH_RX_RLQ,

  /*! incoming broadcast bitrate in bit/s */
  OONF_LAYER2_NEIGH_RX_BC_BITRATE,

  /*! incoming broadcast loss in 1/100 */
  OONF_LAYER2_NEIGH_RX_BC_LOSS,

  /*! latency to neighbor in microseconds */
  OONF_LAYER2_NEIGH_LATENCY,

  /*! available resources of radio (0-100) */
  OONF_LAYER2_NEIGH_RESOURCES,

  /*! number of radio hops to neighbor, only available for multihop capable radios */
  OONF_LAYER2_NEIGH_RADIO_HOPCOUNT,

  /*!
   * IP hopcount (including ethernet between radio and router) to neighbor router,
   * only available for multihop capable radios
   */
  OONF_LAYER2_NEIGH_IP_HOPCOUNT,

  /*! outgoing frame error rate in 1/100 */
  OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE,

  /*! incoming frame error rate in 1/100 */
  OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE,

  /*! outgoing frame error rate used packet size in bytes */
  OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE_PKTSIZE,

  /*! incoming frame error rate used packet size in bytes */
  OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE_PKTSIZE,

  /*! number of neighbor metrics */
  OONF_LAYER2_NEIGH_COUNT,
};

/**
 * representation of a layer2 interface
 */
struct oonf_layer2_net {
  /*! name of local interface */
  char name[IF_NAMESIZE];

  /*! optional identification string */
  char if_ident[64];

  /*! interface type */
  enum oonf_layer2_network_type if_type;

  /*! interface data is delivered by DLEP */
  bool if_dlep;

  /*! interface listener to keep track of events and local mac address */
  struct os_interface_listener if_listener;

  /*! tree of remote neighbors */
  struct avl_tree neighbors;

  /*! tree of IP addresses/prefixes of local radio/modem */
  struct avl_tree local_peer_ips;

  /*! global tree of all remote neighbor IPs */
  struct avl_tree remote_neighbor_ips;

  /*! absolute timestamp when network has been active last */
  uint64_t last_seen;

  /*! network wide layer 2 data */
  struct oonf_layer2_data data[OONF_LAYER2_NET_COUNT];

  /*! default values of neighbor layer2 data */
  struct oonf_layer2_data neighdata[OONF_LAYER2_NEIGH_COUNT];

  /*! node to hook into global l2network tree */
  struct avl_node _node;
};

/**
 * IP addresses that are attached to a local radio/modem
 */
struct oonf_layer2_peer_address {
  /*! ip address attached to a local radio/modem */
  struct netaddr ip;

  /*! backlink to layer2 network */
  struct oonf_layer2_net *l2net;

  /*! origin of this address */
  const struct oonf_layer2_origin *origin;

  /*! node for global tree of network IP addresses */
  struct avl_node _global_node;

  /*! node for tree of ip addresses in network */
  struct avl_node _net_node;
};

/**
 * unique key of a layer2 neighbor
 */
struct oonf_layer2_neigh_key {
  /*! mac address of the neighbor */
  struct netaddr addr;

  /*! length of link id in octets */
  uint8_t link_id_length;

  /*! stored link id of neighbor (padded with zero bytes) */
  uint8_t link_id[OONF_LAYER2_MAX_LINK_ID];
};

/**
 * String buffer for text representation of neighbor key
 */
union oonf_layer2_neigh_key_str {
  struct netaddr_str nbuf;
  char buf[sizeof(struct netaddr_str) + 5 + 16*2];
};

enum oonf_layer2_neigh_mods {
  OONF_LAYER2_NEIGH_MODIFY_NONE       = 0,
  OONF_LAYER2_NEIGH_MODIFY_NEXTHOP_V4 = 1<<0,
  OONF_LAYER2_NEIGH_MODIFY_NEXTHOP_V6 = 1<<1,
  OONF_LAYER2_NEIGH_MODIFY_LASTSEEN   = 1<<2,
};

/**
 * representation of a remote layer2 neighbor
 */
struct oonf_layer2_neigh {
  /*! remote mac address of neighbor */
  struct oonf_layer2_neigh_key key;

  /*! back pointer to layer2 network */
  struct oonf_layer2_net *network;

  /*! fields modified since last commit */
  enum oonf_layer2_neigh_mods modified;

  /* (linklocal) ip address to read neighbor with IPv4 */
  struct netaddr _next_hop_v4;

  /* (linklocal) ip address to read neighbor with IPv6 */
  struct netaddr _next_hop_v6;

  /*! tree of proxied destinations */
  struct avl_tree destinations;

  /*! tree of IP addresses/prefixes of remote neighbor router */
  struct avl_tree remote_neighbor_ips;

  /*! absolute timestamp when neighbor has been active last */
  uint64_t _last_seen;

  /*! neigbor layer 2 data */
  struct oonf_layer2_data data[OONF_LAYER2_NEIGH_COUNT];

  /*! node to hook into tree of layer2 network */
  struct avl_node _node;
};

/**
 * IP addresses that are attached to a remote router
 */
struct oonf_layer2_neighbor_address {
  /*! ip address attached to a remote router */
  struct netaddr ip;

  /*! backlink to layer2 neighbor*/
  struct oonf_layer2_neigh *l2neigh;

  /*! origin of this address */
  const struct oonf_layer2_origin *origin;

  /*! (interface) global tree of neighbor IP addresses */
  struct avl_node _net_node;

  /*! node for tree of ip addresses */
  struct avl_node _neigh_node;
};

/**
 * representation of a bridged MAC address behind a layer2 neighbor
 */
struct oonf_layer2_destination {
  /*! proxied mac address behind a layer2 neighbor */
  struct netaddr destination;

  /*! back pointer to layer2 neighbor */
  struct oonf_layer2_neigh *neighbor;

  /*! origin of this proxied address */
  const struct oonf_layer2_origin *origin;

  /*! node to hook into tree of layer2 neighbor */
  struct avl_node _node;
};

struct oonf_layer2_lid {
  struct netaddr mac;

  uint32_t next_id;

  struct avl_node _node;
};

EXPORT void oonf_layer2_origin_add(struct oonf_layer2_origin *origin);
EXPORT void oonf_layer2_origin_remove(struct oonf_layer2_origin *origin);

EXPORT int oonf_layer2_data_parse_string(
  union oonf_layer2_value *value, const struct oonf_layer2_metadata *meta, const char *input);
EXPORT const char *oonf_layer2_data_to_string(
  char *buffer, size_t length, const struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta, bool raw);
EXPORT bool oonf_layer2_data_set(struct oonf_layer2_data *data, const struct oonf_layer2_origin *origin,
  const struct oonf_layer2_metadata *meta, const union oonf_layer2_value *input);
EXPORT bool oonf_layer2_data_set_int64(struct oonf_layer2_data *l2data, const struct oonf_layer2_origin *origin,
  const struct oonf_layer2_metadata *meta, int64_t integer, uint64_t scaling);
EXPORT bool oonf_layer2_data_compare(const union oonf_layer2_value *left, const union oonf_layer2_value *right,
  enum oonf_layer2_data_comparator_type comparator, enum oonf_layer2_data_type data_type);
EXPORT enum oonf_layer2_data_comparator_type oonf_layer2_data_get_comparator(const char *);
EXPORT const char *oonf_layer2_data_get_comparator_string(enum oonf_layer2_data_comparator_type type);
EXPORT const char *oonf_layer2_data_get_type_string(const struct oonf_layer2_metadata *meta);

EXPORT struct oonf_layer2_net *oonf_layer2_net_add(const char *ifname);
EXPORT bool oonf_layer2_net_remove(struct oonf_layer2_net *, const struct oonf_layer2_origin *origin);
EXPORT bool oonf_layer2_net_cleanup(
  struct oonf_layer2_net *l2net, const struct oonf_layer2_origin *origin, bool cleanup_neigh);
EXPORT bool oonf_layer2_net_commit(struct oonf_layer2_net *);
EXPORT void oonf_layer2_net_relabel(struct oonf_layer2_net *l2net, const struct oonf_layer2_origin *new_origin,
  const struct oonf_layer2_origin *old_origin);
EXPORT struct oonf_layer2_peer_address *oonf_layer2_net_add_ip(
  struct oonf_layer2_net *l2net, const struct oonf_layer2_origin *origin, const struct netaddr *ip);
EXPORT int oonf_layer2_net_remove_ip(struct oonf_layer2_peer_address *ip, const struct oonf_layer2_origin *origin);
EXPORT struct oonf_layer2_neighbor_address *oonf_layer2_net_get_best_neighbor_match(const struct netaddr *addr);
EXPORT struct avl_tree *oonf_layer2_net_get_remote_ip_tree(void);

EXPORT int oonf_layer2_neigh_generate_lid(struct oonf_layer2_neigh_key *, struct oonf_layer2_origin *origin, const struct netaddr *mac);
EXPORT struct oonf_layer2_neigh *oonf_layer2_neigh_add_lid(struct oonf_layer2_net *, const struct oonf_layer2_neigh_key *key);
EXPORT bool oonf_layer2_neigh_cleanup(struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *origin);
EXPORT bool oonf_layer2_neigh_remove(struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *origin);
EXPORT bool oonf_layer2_neigh_commit(struct oonf_layer2_neigh *l2neigh);
EXPORT void oonf_layer2_neigh_relabel(struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *new_origin,
  const struct oonf_layer2_origin *old_origin);
EXPORT int oonf_layer2_neigh_set_nexthop(struct oonf_layer2_neigh *neigh, const struct netaddr *nexthop);
EXPORT struct oonf_layer2_neighbor_address *oonf_layer2_neigh_add_ip(
  struct oonf_layer2_neigh *l2neigh, const struct oonf_layer2_origin *origin, const struct netaddr *ip);
EXPORT int oonf_layer2_neigh_remove_ip(
  struct oonf_layer2_neighbor_address *ip, const struct oonf_layer2_origin *origin);

EXPORT struct oonf_layer2_destination *oonf_layer2_destination_add(
  struct oonf_layer2_neigh *l2neigh, const struct netaddr *destination, const struct oonf_layer2_origin *origin);
EXPORT void oonf_layer2_destination_remove(struct oonf_layer2_destination *);

EXPORT struct oonf_layer2_data *oonf_layer2_neigh_query(
  const char *ifname, const struct netaddr *l2neigh, enum oonf_layer2_neighbor_index idx, bool get_default);
EXPORT struct oonf_layer2_data *oonf_layer2_neigh_add_path(
  const char *ifname, const struct netaddr *l2neigh_addr, enum oonf_layer2_neighbor_index idx);
EXPORT struct oonf_layer2_data *oonf_layer2_neigh_get_data(
  struct oonf_layer2_neigh *l2neigh, enum oonf_layer2_neighbor_index idx);

EXPORT const struct oonf_layer2_metadata *oonf_layer2_neigh_metadata_get(enum oonf_layer2_neighbor_index);
EXPORT const struct oonf_layer2_metadata *oonf_layer2_net_metadata_get(enum oonf_layer2_network_index);
EXPORT const char *oonf_layer2_cfg_get_l2net_key(size_t index, const void *unused);
EXPORT const char *oonf_layer2_cfg_get_l2neigh_key(size_t index, const void *unused);
EXPORT const char *oonf_layer2_cfg_get_l2comp(size_t index, const void *unused);
EXPORT int oonf_layer2_validate_mac_lid(
  const struct cfg_schema_entry *entry, const char *section_name, const char *value, struct autobuf *out);
EXPORT void oonf_layer2_help_mac_lid(const struct cfg_schema_entry *entry, struct autobuf *out);
EXPORT int oonf_layer2_tobin_mac_lid(const struct cfg_schema_entry *s_entry, const struct const_strarray *value, void *reference);

EXPORT const char *oonf_layer2_net_get_type_name(enum oonf_layer2_network_type);
EXPORT enum oonf_layer2_network_type oonf_layer2_get_type(const char *name);

EXPORT struct avl_tree *oonf_layer2_get_net_tree(void);
EXPORT struct avl_tree *oonf_layer2_get_origin_tree(void);
EXPORT int oonf_layer2_avlcmp_neigh_key(const void *p1, const void *p2);
EXPORT const char *oonf_layer2_neigh_key_to_string(union oonf_layer2_neigh_key_str *buf,
    const struct oonf_layer2_neigh_key *key, bool show_mac);
EXPORT int oonf_layer2_neigh_key_from_string(struct oonf_layer2_neigh_key *key, const char *string);

/**
 * Checks if a layer2 originator is registered
 * @param origin originator
 * @return true if registered, false otherwise
 */
static INLINE bool
oonf_layer2_origin_is_added(const struct oonf_layer2_origin *origin) {
  return avl_is_node_added(&origin->_node);
}

/**
 * Get a layer-2 origin object from the database
 * @param ifname name of origin
 * @return origin object, NULL if not found
 */
static INLINE struct oonf_layer2_origin *
oonf_layer2_origin_get(const char *name) {
  struct oonf_layer2_origin *l2origin;
  return avl_find_element(oonf_layer2_get_origin_tree(), name, l2origin, _node);
}


/**
 * Get a layer-2 interface object from the database
 * @param ifname name of interface
 * @return layer-2 addr object, NULL if not found
 */
static INLINE struct oonf_layer2_net *
oonf_layer2_net_get(const char *ifname) {
  struct oonf_layer2_net *l2net;
  return avl_find_element(oonf_layer2_get_net_tree(), ifname, l2net, _node);
}

/**
 * Get a layer-2 local peer ip address object from the database
 * @param l2net layer-2 network/interface object
 * @param addr ip address of local radio/modem
 * @return layer-2 ip address object, NULL if not found
 */
static INLINE struct oonf_layer2_peer_address *
oonf_layer2_net_get_local_ip(const struct oonf_layer2_net *l2net, const struct netaddr *addr) {
  struct oonf_layer2_peer_address *l2ip;
  return avl_find_element(&l2net->local_peer_ips, addr, l2ip, _net_node);
}

/**
 * Get a layer-2 ip address object from the database
 * @param l2net layer-2 network object
 * @param addr ip address of remote router
 * @return layer-2 ip address object, NULL if not found
 */
static INLINE struct oonf_layer2_neighbor_address *
oonf_layer2_net_get_remote_ip(const struct oonf_layer2_net *l2net, const struct netaddr *addr) {
  struct oonf_layer2_neighbor_address *l2ip;
  return avl_find_element(&l2net->remote_neighbor_ips, addr, l2ip, _net_node);
}

/**
 * Add a layer 2 neighbor without supplying a link-id
 * @param l2net layer-2 network object
 * @param l2neigh layer2 address of neighbor
 * @return layer2 neighbor address object, NULL if out of memory
 */
static INLINE struct oonf_layer2_neigh *
oonf_layer2_neigh_add(struct oonf_layer2_net *net, const struct netaddr *l2neigh) {
  struct oonf_layer2_neigh_key key;

  memset(&key, 0, sizeof(key));
  memcpy(&key.addr, l2neigh, sizeof(*l2neigh));
  return oonf_layer2_neigh_add_lid(net, &key);
}

/**
 * Get a layer-2 neighbor object from the database
 * @param l2net layer-2 network/interface object
 * @param addr remote mac address of neighbor
 * @return layer-2 neighbor object, NULL if not found
 */
static INLINE struct oonf_layer2_neigh *
oonf_layer2_neigh_get(const struct oonf_layer2_net *l2net, const struct netaddr *addr) {
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_neigh_key key;

  memset(&key, 0, sizeof(key));
  memcpy(&key.addr, addr, sizeof(*addr));
  return avl_find_element(&l2net->neighbors, &key, l2neigh, _node);
}

/**
 * Get a layer-2 neighbor object from the database
 * @param l2net layer-2 network/interface object
 * @param key unique key of remote neighbor
 * @return layer-2 neighbor object, NULL if not found
 */
static INLINE struct oonf_layer2_neigh *
oonf_layer2_neigh_get_lid(const struct oonf_layer2_net *l2net, const struct oonf_layer2_neigh_key *key) {
  struct oonf_layer2_neigh *l2neigh;
  return avl_find_element(&l2net->neighbors, key, l2neigh, _node);
}

/**
 * Check if a specific element of a neighbor was modified
 * @param neigh layer-2 neighbor object
 * @param mod_mask a binary mask of elements that can be modified
 * @return true if one of the elements was modified, false otherwise
 */
static INLINE bool
oonf_layer2_neigh_is_modified(const struct oonf_layer2_neigh *neigh, enum oonf_layer2_neigh_mods mod_mask) {
  return (neigh->modified & mod_mask) != 0;
}

/**
 * Get the next hop (stored in the neighbor) of a certain address type
 * @param neigh layer-2 neighbor object
 * @param af_type AF_INET or AF_INET6
 * @return next hop addres object, might be unspecified
 */
static INLINE const struct netaddr *
oonf_layer2_neigh_get_nexthop(const struct oonf_layer2_neigh *neigh, int af_type) {
  switch (af_type) {
    case AF_INET:
      return &neigh->_next_hop_v4;
    case AF_INET6:
      return &neigh->_next_hop_v6;
    default:
      return NULL;
  }
}

/**
 * Check if neighbor has a next hop of a certain address type
 * @param neigh layer-2 neighbor object
 * @param af_type AF_INET or AF_INET6
 * @return true if next hop exists, false otherwise
 */
static INLINE bool
oonf_layer2_neigh_has_nexthop(const struct oonf_layer2_neigh *neigh, int af_type) {
  const struct netaddr *next_hop;

  next_hop = oonf_layer2_neigh_get_nexthop(neigh, af_type);
  return next_hop != NULL && netaddr_get_address_family(next_hop) == af_type;
}

/**
 * @param neigh layer-2 neighbor object
 * @return time when the neighbor has been seen last
 */
static INLINE uint64_t
oonf_layer2_neigh_get_lastseen(const struct oonf_layer2_neigh *neigh) {
  return neigh->_last_seen;
}

/**
 * Sets when a neighbor has been seen last
 * @param neigh layer-2 neighbor object
 * @param lastseen time when the neighbor has been seen last
 */
static INLINE void
oonf_layer2_neigh_set_lastseen(struct oonf_layer2_neigh *neigh, uint64_t lastseen) {
  if (neigh->_last_seen != lastseen) {
    neigh->_last_seen = lastseen;
    neigh->modified |= OONF_LAYER2_NEIGH_MODIFY_LASTSEEN;
  }
}

/**
 * Get a layer-2 ip address object from the database
 * @param l2neigh layer-2 neighbor object
 * @param addr ip address of remote router
 * @return layer-2 ip address object, NULL if not found
 */
static INLINE struct oonf_layer2_neighbor_address *
oonf_layer2_neigh_get_remote_ip(const struct oonf_layer2_neigh *l2neigh, const struct netaddr *addr) {
  struct oonf_layer2_neighbor_address *l2ip;
  return avl_find_element(&l2neigh->remote_neighbor_ips, addr, l2ip, _neigh_node);
}

/**
 * Get a layer-2 destination (secondary MAC) for a neighbor
 * @param l2neigh layer-2 neighbor object
 * @param destination mac address of destination
 * @return layer-2 destination object, NULL if not found
 */
static INLINE struct oonf_layer2_destination *
oonf_layer2_destination_get(const struct oonf_layer2_neigh *l2neigh, const struct netaddr *destination) {
  struct oonf_layer2_destination *l2dst;
  return avl_find_element(&l2neigh->destinations, destination, l2dst, _node);
}

/**
 * @param l2data layer-2 data object
 * @return true if object contains a value, false otherwise
 */
static INLINE bool
oonf_layer2_data_has_value(const struct oonf_layer2_data *l2data) {
  return l2data->_origin != NULL && l2data->_meta != NULL;
}

/**
 * @param l2data layer-2 data object
 * @return type of data in object
 */
static INLINE enum oonf_layer2_data_type
oonf_layer2_data_get_type(const struct oonf_layer2_data *l2data) {
  return l2data->_meta->type;
}

/**
 * @param buffer pointer to int64 data storage
 * @param l2data layer-2 data object
 * @param scale scaling factor of the decimal point, 0 to keep data scaling
 * @return 0 if value was read, -1 if it was the wrong type
 */
static INLINE int
oonf_layer2_data_read_int64(int64_t *buffer, const struct oonf_layer2_data *l2data, uint64_t scale) {
  if (!oonf_layer2_data_has_value(l2data)
      || oonf_layer2_data_get_type(l2data) != OONF_LAYER2_INTEGER_DATA) {
    return -1;
  }
  if (!scale) {
    scale = l2data->_meta->scaling;
  }
  if (scale > l2data->_meta->scaling) {
    *buffer =  l2data->_value.integer * (scale / l2data->_meta->scaling);
  }
  else {
    *buffer = l2data->_value.integer / (l2data->_meta->scaling / scale);
  }
  return 0;
}

/**
 * @param l2data layer-2 data object
 * @param scale scaling factor of the decimal point
 * @param def default value to return
 * @return value of data object, default value if not net
 */
static INLINE int64_t
oonf_layer2_data_get_int64(const struct oonf_layer2_data *l2data, uint64_t scale, int64_t def) {
  int64_t result = def;

  oonf_layer2_data_read_int64(&result, l2data, scale);
  return result;
}

/**
 * @param buffer pointer to boolean data storage
 * @param l2data layer-2 data object
 * @return 0 if value was read, -1 if it was the wrong type
 */
static INLINE int
oonf_layer2_data_read_boolean(bool *buffer, const struct oonf_layer2_data *l2data) {
  if (!l2data->_meta ||  oonf_layer2_data_get_type(l2data) != OONF_LAYER2_BOOLEAN_DATA) {
    return -1;
  }
  *buffer = l2data->_value.boolean;
  return 0;
}

/**
 * @param l2data layer-2 data object
 * @return true if the data object contains no data, not a network data
 *   or network data which is unspecified, false otherwise
 */
static INLINE bool
oonf_layer2_data_netaddr_is_unspec(const struct oonf_layer2_data *l2data) {
  return !l2data->_meta
      || oonf_layer2_data_get_type(l2data) != OONF_LAYER2_NETWORK_DATA
      || netaddr_is_unspec(&l2data->_value.addr);
}

/**
 * @param l2data layer-2 data object
 * @return pointer to netaddr object, NULL if not available
 */
static INLINE const struct netaddr *
oonf_layer2_data_get_netaddr(const struct oonf_layer2_data *l2data) {
  if (!l2data->_meta ||  oonf_layer2_data_get_type(l2data) != OONF_LAYER2_NETWORK_DATA) {
    return NULL;
  }
  return &l2data->_value.addr;
}

/**
 * @param l2data layer-2 data object
 * @return true if the data object contains no data, not socket data
 *   or socket data which is unspecified, false otherwise
 */
static INLINE bool
oonf_layer2_data_socket_is_unspec(const struct oonf_layer2_data *l2data) {
  return !l2data->_meta
      || oonf_layer2_data_get_type(l2data) != OONF_LAYER2_SOCKET_DATA
      || netaddr_is_unspec(&l2data->_value.addr);
}

/**
 * @param l2data layer-2 data object
 * @return pointer to netaddr socket object, NULL if not available
 */
static INLINE const union netaddr_socket *
oonf_layer2_data_get_socket(const struct oonf_layer2_data *l2data) {
  if (!l2data->_meta ||  oonf_layer2_data_get_type(l2data) != OONF_LAYER2_SOCKET_DATA) {
    return NULL;
  }
  return &l2data->_value.socket;
}

/**
 * Sets a layer-2 object with network data
 * @param l2data layer-2 data object
 * @param origin layer-2 origin
 * @param meta layer-2 metadata
 * @param addr network data object
 * @return true if the data could be set, false otherwise
 */
static INLINE bool
oonf_layer2_data_set_netaddr(struct oonf_layer2_data *l2data, const struct oonf_layer2_origin *origin,
    const struct oonf_layer2_metadata *meta, const struct netaddr *addr) {
  const union oonf_layer2_value *value = (union oonf_layer2_value *)addr;
  if (l2data->_meta != NULL && l2data->_meta != meta) {
    return false;
  }
  return oonf_layer2_data_set(l2data, origin, meta, value);
}

/**
 * Sets a layer-2 object with socket data
 * @param l2data layer-2 data object
 * @param origin layer-2 origin
 * @param meta layer-2 metadata
 * @param sock socket data
 * @return true if the data could be set, false otherwise
 */
static INLINE bool
oonf_layer2_data_set_socket(struct oonf_layer2_data *l2data, const struct oonf_layer2_origin *origin,
    const struct oonf_layer2_metadata *meta, const union netaddr_socket *sock) {
  const union oonf_layer2_value *value = (union oonf_layer2_value *)sock;
  if (l2data->_meta != NULL && l2data->_meta != meta) {
    return false;
  }
  return oonf_layer2_data_set(l2data, origin, meta, value);
}

/**
 * @param l2data layer-2 data object
 * @param def default value to return
 * @return value of data object, default value if not net
 */
static INLINE bool
oonf_layer2_data_get_boolean(const struct oonf_layer2_data *l2data, bool def) {
  bool result = def;

  oonf_layer2_data_read_boolean(&result, l2data);
  return result;
}

/**
 * @param l2data layer-2 data object
 * @return originator of data value
 */
static INLINE const struct oonf_layer2_origin *
oonf_layer2_data_get_origin(const struct oonf_layer2_data *l2data) {
  return l2data->_origin;
}

/**
 * Sets the originator of a layer-2 data object
 * @param l2data layer-2 data object
 * @param origin originator of data value
 */
static INLINE void
oonf_layer2_data_set_origin(struct oonf_layer2_data *l2data, const struct oonf_layer2_origin *origin) {
  l2data->_origin = origin;
}


/**
 * Convert a text input into a layer-2 data object
 * @param data destination buffer
 * @param origin layer-2 origin of data
 * @param meta layer-2 metadata object
 * @param input text input
 * @return true if conversion was successful, false otherwise
 */
static INLINE bool
oonf_layer2_data_from_string(struct oonf_layer2_data *data, const struct oonf_layer2_origin *origin,
  const struct oonf_layer2_metadata *meta, const char *input) {
  union oonf_layer2_value value;

  if (oonf_layer2_data_parse_string(&value, meta, input)) {
    return false;
  }
  return oonf_layer2_data_set(data, origin, meta, &value);
}

/**
 * Converts a network data object into a string
 * @param buffer destination string buffer
 * @param length length of destination buffer
 * @param l2net layer-2 network object
 * @param idx network data object index
 * @param raw true for raw conversion, false for iso-prefix conversion
 */
static INLINE const char *
oonf_layer2_net_data_to_string(
  char *buffer, size_t length, struct oonf_layer2_net *l2net, enum oonf_layer2_network_index idx, bool raw) {
  return oonf_layer2_data_to_string(buffer, length, &l2net->data[idx], oonf_layer2_net_metadata_get(idx), raw);
}

/**
 * Converts a network specific neighbor default data object into a string
 * @param buffer destination string buffer
 * @param length length of destination buffer
 * @param l2net layer-2 network object
 * @param idx neighbor data object index
 * @param raw true for raw conversion, false for iso-prefix conversion
 */
static INLINE const char *
oonf_layer2_net_default_data_to_string(
  char *buffer, size_t length, struct oonf_layer2_net *l2net, enum oonf_layer2_neighbor_index idx, bool raw) {
  return oonf_layer2_data_to_string(buffer, length, &l2net->neighdata[idx], oonf_layer2_neigh_metadata_get(idx), raw);
}


/**
 * Converts a neighbor data object into a string
 * @param buffer destination string buffer
 * @param length length of destination buffer
 * @param l2neigh layer-2 neighbor object
 * @param idx neighbor data object index
 * @param raw true for raw conversion, false for iso-prefix conversion
 */
static INLINE const char *
oonf_layer2_neigh_data_to_string(
  char *buffer, size_t length, struct oonf_layer2_neigh *l2neigh, enum oonf_layer2_neighbor_index idx, bool raw) {
  return oonf_layer2_data_to_string(buffer, length, &l2neigh->data[idx], oonf_layer2_neigh_metadata_get(idx), raw);
}

/**
 * Set the value of a layer-2 data object
 * @param l2data layer-2 data object
 * @param origin originator of value
 * @param meta layer2 metadata, NULL for same metadata as l2data object
 * @param boolean new value for data object
 * @return true if value was overwrite, false otherwise
 */
static INLINE bool
oonf_layer2_data_set_bool(struct oonf_layer2_data *l2data, const struct oonf_layer2_origin *origin,
    const struct oonf_layer2_metadata *meta, bool boolean) {
  union oonf_layer2_value value = { 0 };
  value.boolean = boolean;
  return oonf_layer2_data_set(l2data, origin, meta, &value);
}

/**
 * Parse a string into a network data base layer-2 data object
 * @param data destination buffer
 * @param idx network data index
 * @param origin layer-2 data origin
 * @param input input string buffer
 * @return 0 if everything is okay, -1 otherwise
 */
static INLINE int
oonf_layer2_net_data_from_string(struct oonf_layer2_data *data, enum oonf_layer2_network_index idx,
  struct oonf_layer2_origin *origin, const char *input) {
  return oonf_layer2_data_from_string(data, origin, oonf_layer2_net_metadata_get(idx), input);
}

/**
 * Parse a string into a neighbor data base layer-2 data object
 * @param data destination buffer
 * @param idx neighbor data index
 * @param origin layer-2 data origin
 * @param input input string buffer
 * @return 0 if everything is okay, -1 otherwise
 */
static INLINE int
oonf_layer2_neigh_data_from_string(struct oonf_layer2_data *data, enum oonf_layer2_neighbor_index idx,
  struct oonf_layer2_origin *origin, const char *input) {
  return oonf_layer2_data_from_string(data, origin, oonf_layer2_neigh_metadata_get(idx), input);
}

/**
 * Removes the value of a layer-2 data object
 * @param l2data layer-2 data object
 */
static INLINE void
oonf_layer2_data_reset(struct oonf_layer2_data *l2data) {
  l2data->_meta = NULL;
  l2data->_origin = NULL;
}

#endif /* OONF_LAYER2_H_ */
