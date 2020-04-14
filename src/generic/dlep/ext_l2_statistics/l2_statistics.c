
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
  { DLEP_R_FRAME_ERROR_RATE_TLV, 1, 1 },
  { DLEP_T_FRAME_ERROR_RATE_TLV, 1, 1 },
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
    .length = 1,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_T_FRAME_ERROR_RATE_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_FRAME_ERROR_RATE,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
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
