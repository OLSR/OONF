
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

#include <oonf/generic/dlep/ext_radio_attributes/radio_attributes.h>

/* peer initialization ack */
static const uint16_t _session_initack_tlvs[] = {
  DLEP_MCS_BY_PROBING,
  DLEP_RX_ONLY_UNICAST,
  DLEP_TX_ONLY_UNICAST,
  DLEP_CAN_MULTIHOP,
};

/* peer update */
static const uint16_t _peer_session_tlvs[] = {
  DLEP_MCS_BY_PROBING,
  DLEP_RX_ONLY_UNICAST,
  DLEP_TX_ONLY_UNICAST,
  DLEP_CAN_MULTIHOP,
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
};

/* supported TLVs of this extension */
static struct dlep_extension_tlv _tlvs[] = {
  { DLEP_MCS_BY_PROBING, 1, 1 },
  { DLEP_RX_ONLY_UNICAST, 1, 1 },
  { DLEP_TX_ONLY_UNICAST, 1, 1 },
  { DLEP_CAN_MULTIHOP, 1, 1 },
};

static struct dlep_network_mapping _net_mappings[] = {
  {
    .dlep = DLEP_MCS_BY_PROBING,
    .layer2 = OONF_LAYER2_NET_MCS_BY_PROBING,
    .length = 1,
    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_RX_ONLY_UNICAST,
    .layer2 = OONF_LAYER2_NET_RX_ONLY_UNICAST,
    .length = 1,
    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_TX_ONLY_UNICAST,
    .layer2 = OONF_LAYER2_NET_RADIO_MULTIHOP,
    .length = 1,
    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CAN_MULTIHOP,
    .layer2 = OONF_LAYER2_NET_TX_ONLY_UNICAST,
    .length = 1,
    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
};

/* DLEP base extension, radio side */
static struct dlep_extension _radio_attributes = {
  .id = DLEP_EXTENSION_RADIO_ATTRIBUTES,
  .name = "radio attributes",

  .signals = _signals,
  .signal_count = ARRAYSIZE(_signals),
  .tlvs = _tlvs,
  .tlv_count = ARRAYSIZE(_tlvs),
  .if_mapping = _net_mappings,
  .if_mapping_count = ARRAYSIZE(_net_mappings),
};

/**
 * Get the layer2 statistics DLEP extension
 * @return this extension
 */
struct dlep_extension *
dlep_radio_attributes_init(void) {
  dlep_extension_add(&_radio_attributes);
  return &_radio_attributes;
}
