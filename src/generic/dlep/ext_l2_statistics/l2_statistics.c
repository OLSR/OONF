
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

#include <oonf/generic/dlep/ext_l2_statistics/l2_statistics.h>

static int _reader_error_rate(
  struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling);
static int _writer_error_rate(
    struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling);

/* peer initialization ack */
static const uint16_t _session_initack_tlvs[] = {
  DLEP_FRAMES_R_TLV,
  DLEP_FRAMES_T_TLV,
  DLEP_FRAMES_RETRIES_TLV,
  DLEP_FRAMES_FAILED_TLV,
  DLEP_BYTES_R_TLV,
  DLEP_BYTES_T_TLV,
  DLEP_THROUGHPUT_T_TLV,
  DLEP_CDRR_BC_TLV,
  DLEP_R_FRAME_ERROR_RATE_TLV,
  DLEP_T_FRAME_ERROR_RATE_TLV,
};

/* peer update */
static const uint16_t _peer_session_tlvs[] = {
  DLEP_FRAMES_R_TLV,
  DLEP_FRAMES_T_TLV,
  DLEP_FRAMES_RETRIES_TLV,
  DLEP_FRAMES_FAILED_TLV,
  DLEP_BYTES_R_TLV,
  DLEP_BYTES_T_TLV,
  DLEP_THROUGHPUT_T_TLV,
  DLEP_CDRR_BC_TLV,
  DLEP_R_FRAME_ERROR_RATE_TLV,
  DLEP_T_FRAME_ERROR_RATE_TLV,
};

/* destination up/update */
static const uint16_t _dst_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
  DLEP_FRAMES_R_TLV,
  DLEP_FRAMES_T_TLV,
  DLEP_FRAMES_RETRIES_TLV,
  DLEP_FRAMES_FAILED_TLV,
  DLEP_BYTES_R_TLV,
  DLEP_BYTES_T_TLV,
  DLEP_THROUGHPUT_T_TLV,
  DLEP_CDRR_BC_TLV,
  DLEP_R_FRAME_ERROR_RATE_TLV,
  DLEP_T_FRAME_ERROR_RATE_TLV,
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
    .add_radio_tlvs = dlep_extension_radio_write_session_init_ack,
    .process_router = dlep_extension_router_process_session_init_ack,
  },
  {
    .id = DLEP_SESSION_UPDATE,
    .supported_tlvs = _peer_session_tlvs,
    .supported_tlv_count = ARRAYSIZE(_peer_session_tlvs),
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
  { DLEP_FRAMES_R_TLV, 8, 8 },
  { DLEP_FRAMES_T_TLV, 8, 8 },
  { DLEP_FRAMES_RETRIES_TLV, 8, 8 },
  { DLEP_FRAMES_FAILED_TLV, 8, 8 },
  { DLEP_BYTES_R_TLV, 8, 8 },
  { DLEP_BYTES_T_TLV, 8, 8 },
  { DLEP_THROUGHPUT_T_TLV, 8, 8 },
  { DLEP_CDRR_BC_TLV, 8, 8 },
  { DLEP_R_FRAME_ERROR_RATE_TLV, 3, 3 },
  { DLEP_T_FRAME_ERROR_RATE_TLV, 3, 3 },
};

static struct dlep_neighbor_mapping _neigh_mappings[] = {
  {
    .dlep = DLEP_FRAMES_R_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_FRAMES,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_FRAMES_T_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_FRAMES,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_FRAMES_RETRIES_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_RETRIES,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_FRAMES_FAILED_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_FAILED,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_BYTES_R_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_BYTES,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_BYTES_T_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_BYTES,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_THROUGHPUT_T_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_THROUGHPUT,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CDRR_BC_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_BC_BITRATE,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_R_FRAME_ERROR_RATE_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE,
    .length = 3,
    .scaling = 1,

    .from_tlv = _reader_error_rate,
    .to_tlv = _writer_error_rate,
  },
  {
    .dlep = DLEP_T_FRAME_ERROR_RATE_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE,
    .length = 3,
    .scaling = 1,

    .from_tlv = _reader_error_rate,
    .to_tlv = _writer_error_rate,
  },
};

/* DLEP base extension, radio side */
static struct dlep_extension _l2_stats = {
  .id = DLEP_EXTENSION_L2_STATS,
  .name = "l2 stats",

  .signals = _signals,
  .signal_count = ARRAYSIZE(_signals),
  .tlvs = _tlvs,
  .tlv_count = ARRAYSIZE(_tlvs),
  .neigh_mapping = _neigh_mappings,
  .neigh_mapping_count = ARRAYSIZE(_neigh_mappings),
};

/**
 * Get the layer2 statistics DLEP extension
 * @return this extension
 */
struct dlep_extension *
dlep_l2_statistics_init(void) {
  dlep_extension_add(&_l2_stats);
  return &_l2_stats;
}

/**
 * Read frame error rate TLV into layer2 database objects
 * @param data layer2 network data array
 * @param meta metadata description for data
 * @param session dlep session
 * @param dlep_tlv dlep TLV id
 * @param scaling fixed integer arithmetics scaling factor
 * @return -1 if an error happened, 0 otherwise
 */
static int
_reader_error_rate(struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta,
  struct dlep_session *session, uint16_t dlep_tlv, uint64_t scaling) {
  struct dlep_parser_value *value;
  const uint8_t *dlepvalue;
  uint8_t error_rate;
  uint16_t pkt_size;

  value = dlep_session_get_tlv_value(session, dlep_tlv);
  if (!value) {
    return 0;
  }
  if (scaling != 1 || value->length != 3) {
    return -1;
  }

  /* read binary values */
  dlepvalue = dlep_parser_get_tlv_binary(&session->parser, value);
  memcpy(&error_rate, dlepvalue, 1);
  memcpy(&pkt_size, &dlepvalue[1], 2);
  pkt_size = ntohs(pkt_size);

  /* set error rate */
  oonf_layer2_data_set_int64(data, session->l2_origin, meta, error_rate, scaling);

  switch (dlep_tlv) {
    case DLEP_R_FRAME_ERROR_RATE_TLV:
      data += (OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE_PKTSIZE - OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE);
      meta += (OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE_PKTSIZE - OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE);
      break;
    case DLEP_T_FRAME_ERROR_RATE_TLV:
      data += (OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE_PKTSIZE - OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE);
      meta += (OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE_PKTSIZE - OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE);
      break;
    default:
      return -1;
  }

  /* set error rate pktsize */
  oonf_layer2_data_set_int64(data, session->l2_origin, meta, pkt_size, scaling);
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
_writer_error_rate (struct dlep_writer *writer, struct oonf_layer2_data *data,
  const struct oonf_layer2_metadata *meta, uint16_t tlv, uint16_t length, uint64_t scaling) {
  struct oonf_layer2_data *data2;
  int64_t l2value;
  uint64_t tmp16;
  uint8_t dlep_value[3];

  if (scaling != 1 || length != 3) {
    return -1;
  }
  if (meta->type != OONF_LAYER2_INTEGER_DATA) {
    return -1;
  }

  switch (tlv) {
    case DLEP_R_FRAME_ERROR_RATE_TLV:
      data2 = data + (OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE_PKTSIZE - OONF_LAYER2_NEIGH_RX_FRAME_ERROR_RATE);
      break;
    case DLEP_T_FRAME_ERROR_RATE_TLV:
      data2 = data + (OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE_PKTSIZE - OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE);
      break;
    default:
      return -1;
  }

  if (oonf_layer2_data_read_int64(&l2value, data, scaling)) {
    return 0;
  }
  dlep_value[0] = l2value;

  if (oonf_layer2_data_read_int64(&l2value, data2, scaling)) {
    return 0;
  }
  tmp16 = l2value;
  tmp16 = htons(tmp16);
  memcpy(&dlep_value[1], &tmp16, 2);

  dlep_writer_add_tlv(writer, tlv, &dlep_value[0], length);
  return 0;
}
