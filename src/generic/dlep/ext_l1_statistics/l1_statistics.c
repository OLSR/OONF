
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
#include <oonf/oonf.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_reader.h>
#include <oonf/generic/dlep/dlep_writer.h>

#include <oonf/generic/dlep/ext_l1_statistics/l1_statistics.h>

static int _reader_map_array (struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling, enum oonf_layer2_network_index l2idx);
static int _reader_map_frequency (struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling);
static int _reader_map_bandwidth (struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling);

static int _writer_map_array (struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling,
  enum oonf_layer2_network_index l2idx);
static int _writer_map_frequency (struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling);
static int _writer_map_bandwidth (struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling);

/* peer initialization ack */
static const uint16_t _session_initack_tlvs[] = {
  DLEP_FREQUENCY_TLV,
  DLEP_BANDWIDTH_TLV,
  DLEP_NOISE_LEVEL_TLV,
  DLEP_CHANNEL_ACTIVE_TLV,
  DLEP_CHANNEL_BUSY_TLV,
  DLEP_CHANNEL_RX_TLV,
  DLEP_CHANNEL_TX_TLV,
  DLEP_SIGNAL_RX_TLV,
  DLEP_SIGNAL_TX_TLV,
};
static const uint16_t _session_initack_mandatory[] = {
  DLEP_FREQUENCY_TLV,
  DLEP_BANDWIDTH_TLV,
};

/* peer update */
static const uint16_t _peer_update_tlvs[] = {
  DLEP_FREQUENCY_TLV,
  DLEP_BANDWIDTH_TLV,
  DLEP_NOISE_LEVEL_TLV,
  DLEP_CHANNEL_ACTIVE_TLV,
  DLEP_CHANNEL_BUSY_TLV,
  DLEP_CHANNEL_RX_TLV,
  DLEP_CHANNEL_TX_TLV,
  DLEP_SIGNAL_RX_TLV,
  DLEP_SIGNAL_TX_TLV,
};

/* destination up/update */
static const uint16_t _dst_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
  DLEP_SIGNAL_RX_TLV,
  DLEP_SIGNAL_TX_TLV,
};
static const uint16_t _dst_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
};

/* supported signals of this extension */
static struct dlep_extension_signal _signals[] = {
  {
    .id = DLEP_SESSION_INITIALIZATION_ACK,
    .supported_tlvs = _session_initack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_session_initack_tlvs),
    .mandatory_tlvs = _session_initack_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_session_initack_mandatory),
    .add_radio_tlvs = dlep_extension_radio_write_session_init_ack,
    .process_router = dlep_extension_router_process_session_init_ack,
  },
  {
    .id = DLEP_SESSION_UPDATE,
    .supported_tlvs = _peer_update_tlvs,
    .supported_tlv_count = ARRAYSIZE(_peer_update_tlvs),
    .add_radio_tlvs = dlep_extension_radio_write_session_update,
    .process_router = dlep_extension_router_process_session_update,
  },
  {
    .id = DLEP_DESTINATION_UP,
    .supported_tlvs = _dst_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_tlvs),
    .mandatory_tlvs = _dst_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_dst_mandatory),
    .add_radio_tlvs = dlep_extension_radio_write_destination,
    .process_router = dlep_extension_router_process_destination,
  },
  {
    .id = DLEP_DESTINATION_UPDATE,
    .supported_tlvs = _dst_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_tlvs),
    .mandatory_tlvs = _dst_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_dst_mandatory),
    .add_radio_tlvs = dlep_extension_radio_write_destination,
    .process_router = dlep_extension_router_process_destination,
  },
};

/* supported TLVs of this extension */
static struct dlep_extension_tlv _tlvs[] = {
  { DLEP_FREQUENCY_TLV, 8, 16 },
  { DLEP_BANDWIDTH_TLV, 8, 16 },
  { DLEP_NOISE_LEVEL_TLV, 4, 4 },
  { DLEP_CHANNEL_ACTIVE_TLV, 8, 8 },
  { DLEP_CHANNEL_BUSY_TLV, 8, 8 },
  { DLEP_CHANNEL_RX_TLV, 8, 8 },
  { DLEP_CHANNEL_TX_TLV, 8, 8 },
  { DLEP_SIGNAL_RX_TLV, 4, 4 },
  { DLEP_SIGNAL_TX_TLV, 4, 4 },
};

static struct dlep_neighbor_mapping _neigh_mappings[] = {
  {
    .dlep = DLEP_SIGNAL_RX_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_SIGNAL,
    .length = 4,
    .scaling = 1000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_SIGNAL_TX_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_SIGNAL,
    .length = 4,
    .scaling = 1000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
};

static struct dlep_network_mapping _net_mappings[] = {
  {
    .dlep = DLEP_FREQUENCY_TLV,
    .layer2 = OONF_LAYER2_NET_FREQUENCY_1,
    .length = 8,
    .scaling = 1,

    .from_tlv = _reader_map_frequency,
    .to_tlv = _writer_map_frequency,
  },
  {
    .dlep = DLEP_BANDWIDTH_TLV,
    .layer2 = OONF_LAYER2_NET_BANDWIDTH_1,
    .length = 8,
    .scaling = 1,

    .from_tlv = _reader_map_bandwidth,
    .to_tlv = _writer_map_bandwidth,
  },
  {
    .dlep = DLEP_NOISE_LEVEL_TLV,
    .layer2 = OONF_LAYER2_NET_NOISE,
    .length = 4,
    .scaling = 1000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CHANNEL_ACTIVE_TLV,
    .layer2 = OONF_LAYER2_NET_CHANNEL_ACTIVE,
    .length = 8,
    .scaling = 1000000000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CHANNEL_BUSY_TLV,
    .layer2 = OONF_LAYER2_NET_CHANNEL_BUSY,
    .length = 8,
    .scaling = 1000000000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CHANNEL_RX_TLV,
    .layer2 = OONF_LAYER2_NET_CHANNEL_RX,
    .length = 8,
    .scaling = 1000000000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CHANNEL_TX_TLV,
    .layer2 = OONF_LAYER2_NET_CHANNEL_TX,
    .length = 8,
    .scaling = 1000000000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
};

/* DLEP base extension, radio side */
static struct dlep_extension _l1_stats = {
  .id = DLEP_EXTENSION_L1_STATS,
  .name = "l1 stats",

  .signals = _signals,
  .signal_count = ARRAYSIZE(_signals),
  .tlvs = _tlvs,
  .tlv_count = ARRAYSIZE(_tlvs),
  .neigh_mapping = _neigh_mappings,
  .neigh_mapping_count = ARRAYSIZE(_neigh_mappings),
  .if_mapping = _net_mappings,
  .if_mapping_count = ARRAYSIZE(_net_mappings),
};

/**
 * Get the layer1 statistics DLEP extension
 * @return this extension
 */
struct dlep_extension *
dlep_l1_statistics_init(void) {
  dlep_extension_add(&_l1_stats);
  return &_l1_stats;
}

/**
 * Maps frequency or bandwidth array from DLEP TLVs
 * into layer2 network objects
 * @param data layer2 data object
 * @param session dlep session
 * @param dlep_tlv dlep tlv
 * @param scaling fixed integer arithmetics scaling factor
 * @param l2idx layer2 index
 * @return -1 if an error happened, 0 otherwise
 */
static int
_reader_map_array (struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling, enum oonf_layer2_network_index l2idx) {
  struct dlep_parser_value *value;
  int64_t l2value;
  const uint8_t *dlepvalue;
  uint64_t tmp64[2] = { 0, 0 };

  value = dlep_session_get_tlv_value(session, dlep_tlv);
  if (!value) {
    return 0;
  }

  if (value->length != 8 && value->length != 16) {
    return -1;
  }

  dlepvalue = dlep_parser_get_tlv_binary(&session->parser, value);

  /* extract dlep TLV values and convert to host representation */
  if (value->length == 16) {
    memcpy(&tmp64[1], &dlepvalue[8], 8);
    tmp64[1] = be64toh(tmp64[1]);
  }
  memcpy(&tmp64[0], dlepvalue, 8);
  tmp64[0] = be64toh(tmp64[0]);

  /* copy into signed integer and set to l2 value */
  memcpy(&l2value, &tmp64[0], 8);
  oonf_layer2_data_set_int64(data, session->l2_origin, meta, l2value, scaling);

  if (value->length == 16) {
    switch (l2idx) {
      case OONF_LAYER2_NET_BANDWIDTH_1:
        data += (OONF_LAYER2_NET_BANDWIDTH_2 - OONF_LAYER2_NET_BANDWIDTH_1);
        break;
      case OONF_LAYER2_NET_FREQUENCY_1:
        data += (OONF_LAYER2_NET_FREQUENCY_2 - OONF_LAYER2_NET_FREQUENCY_1);
        break;
      default:
        return -1;
    }

    memcpy(&l2value, &tmp64[1], 8);
    oonf_layer2_data_set_int64(data, session->l2_origin, meta, l2value, scaling);
  }
  return 0;
}

/**
 * Read frequency TLV into layer2 database objects
 * @param data layer2 network data array
 * @param meta metadata description for data
 * @param session dlep session
 * @param dlep_tlv dlep TLV id
 * @param scaling fixed integer arithmetics scaling factor
 * @return -1 if an error happened, 0 otherwise
 */
static int
_reader_map_frequency (struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling) {
  return _reader_map_array (data, meta, session, dlep_tlv, scaling, OONF_LAYER2_NET_FREQUENCY_1);
}

/**
 * Read bandwidth TLV into layer2 database objects
 * @param data layer2 network data array
 * @param meta metadata description for data
 * @param session dlep session
 * @param dlep_tlv dlep TLV id
 * @param scaling fixed integer arithmetics scaling factor
 * @return -1 if an error happened, 0 otherwise
 */
static int
_reader_map_bandwidth (struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling) {
  return _reader_map_array (data, meta, session, dlep_tlv, scaling, OONF_LAYER2_NET_BANDWIDTH_1);
}

/**
 * Map bandwidth or frequency from layer2 network data into
 * DLEP TLV
 * @param writer dlep writer
 * @param data layer2 network data
 * @param tlv dlep tlv id
 * @param length tlv length
 * @param scaling fixed integer arithmetics scaling factor
 * @param l2idx layer2 network index
 * @return -1 if an error happened, 0 otherwise
 */
int
_writer_map_array (struct dlep_writer *writer, struct oonf_layer2_data *data,
    const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling,
    enum oonf_layer2_network_index l2idx) {
  struct oonf_layer2_data *data2;
  int64_t l2value;
  uint64_t tmp64[2];

  if (length != 8 && length != 16) {
    return -1;
  }
  if (meta->type != OONF_LAYER2_INTEGER_DATA) {
    return -1;
  }

  if (length == 16) {
    switch (l2idx) {
      case OONF_LAYER2_NET_FREQUENCY_1:
        data2 = data + (OONF_LAYER2_NET_FREQUENCY_2 - OONF_LAYER2_NET_FREQUENCY_1);
        break;
      case OONF_LAYER2_NET_BANDWIDTH_1:
        data2 = data + (OONF_LAYER2_NET_BANDWIDTH_2 - OONF_LAYER2_NET_BANDWIDTH_1);
        break;
      default:
        return -1;
    }

    if (!oonf_layer2_data_read_int64(&l2value, data2, scaling)) {
      memcpy(&tmp64[1], &l2value, 8);
      tmp64[1] = htobe64(tmp64[1]);
      length = 16;
    }
  }

  l2value = oonf_layer2_data_get_int64(data, scaling, 0);
  memcpy(&tmp64[0], &l2value, 8);
  tmp64[0] = htobe64(tmp64[0]);

  dlep_writer_add_tlv(writer, tlv, &tmp64[0], length);
  return 0;
}

/**
 * Map layer2 frequency to DLEP TLV
 * @param writer dlep writer
 * @param data layer2 network data array
 * @param tlv DLEP tlv id
 * @param length tlv length
 * @param scaling fixed integer arithmetics scaling factor
 * @return -1 if an error happened, 0 otherwise
 */
static int
_writer_map_frequency (struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling) {
  return _writer_map_array (writer, data, meta, tlv, length, scaling, OONF_LAYER2_NET_FREQUENCY_1);
}

/**
 * Map layer2 bandwidth to DLEP TLV
 * @param writer dlep writer
 * @param data layer2 network data array
 * @param tlv DLEP tlv id
 * @param length tlv length
 * @param scaling fixed integer arithmetics scaling factor
 * @return -1 if an error happened, 0 otherwise
 */
static int
_writer_map_bandwidth (struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling) {
  return _writer_map_array (writer, data, meta, tlv, length, scaling, OONF_LAYER2_NET_BANDWIDTH_1);
}
