
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

#include <stdlib.h>

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>

#include <oonf/base/oonf_layer2.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_reader.h>
#include <oonf/generic/dlep/dlep_session.h>
#include <oonf/generic/dlep/dlep_writer.h>

static enum dlep_parser_error _process_interface_specific_update(struct dlep_extension *ext, struct dlep_session *session);

static struct avl_tree _extension_tree;

static uint16_t *_id_array = NULL;
static uint16_t _id_array_length = 0;

/**
 * Initialize the dlep extension system
 */
void
dlep_extension_init(void) {
  avl_init(&_extension_tree, avl_comp_int32, false);
}

/**
 * Cleanup DLEP extension resources
 */
void
dlep_extension_cleanup(void) {
  free(_id_array);
  _id_array = NULL;
  _id_array_length = 0;
}

/**
 * Add a new dlep extension
 * @param ext pointer to initialized extension handler
 */
void
dlep_extension_add(struct dlep_extension *ext) {
  uint16_t *ptr;

  if (avl_is_node_added(&ext->_node)) {
    return;
  }

  /* add to tree */
  ext->_node.key = &ext->id;
  avl_insert(&_extension_tree, &ext->_node);

  /* refresh id array */
  ptr = realloc(_id_array, sizeof(uint16_t) * _extension_tree.count);
  if (!ptr) {
    return;
  }

  _id_array_length = 0;
  _id_array = ptr;

  avl_for_each_element(&_extension_tree, ext, _node) {
    if (ext->id >= 0 && ext->id <= 0xffff) {
      ptr[_id_array_length] = htons(ext->id);
      _id_array_length++;
    }
  }
}

/**
 * Get tree of dlep extensions
 * @return tree of extensions
 */
struct avl_tree *
dlep_extension_get_tree(void) {
  return &_extension_tree;
}

/**
 * Add processing callbacks to DLEP extension
 * @param ext dlep extension
 * @param radio true if radio extension, false if router
 * @param processing array of dlep extension processing handlers
 * @param proc_count number of processing handlers
 */
void
dlep_extension_add_processing(
  struct dlep_extension *ext, bool radio, struct dlep_extension_implementation *processing, size_t proc_count) {
  size_t i, j;

  for (j = 0; j < proc_count; j++) {
    for (i = 0; i < ext->signal_count; i++) {
      if (ext->signals[i].id == processing[j].id) {
        if (radio) {
          ext->signals[i].process_radio = processing[j].process;
          ext->signals[i].add_radio_tlvs = processing[j].add_tlvs;
        }
        else {
          ext->signals[i].process_router = processing[j].process;
          ext->signals[i].add_router_tlvs = processing[j].add_tlvs;
        }
        break;
      }
    }
  }
}

/**
 * Get the array of supported dlep extension ids
 * @param length pointer to length field to store id count
 * @return pointer to array with ids
 */
const uint16_t *
dlep_extension_get_ids(uint16_t *length) {
  *length = _id_array_length;
  return _id_array;
}

/**
 * Handle peer init ack for DLEP extension by automatically
 * mapping oonf_layer2_data to DLEP TLVs
 * @param ext dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
enum dlep_parser_error
dlep_extension_router_process_session_init_ack(struct dlep_extension *ext, struct dlep_session *session) {
  if (session->restrict_signal != DLEP_SESSION_INITIALIZATION_ACK) {
    /* ignore unless we are in initialization mode */
    return DLEP_NEW_PARSER_OKAY;
  }
  return _process_interface_specific_update(ext, session);
}

/**
 * Handle peer update for DLEP extension by automatically
 * mapping oonf_layer2_data to DLEP TLVs
 * @param ext dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
enum dlep_parser_error
dlep_extension_router_process_session_update(struct dlep_extension *ext, struct dlep_session *session) {
  if (session->restrict_signal != DLEP_ALL_SIGNALS) {
    /* ignore unless we have an established session */
    return DLEP_NEW_PARSER_OKAY;
  }

  return _process_interface_specific_update(ext, session);
}

int
dlep_extension_get_l2_neighbor_key(struct oonf_layer2_neigh_key *key, struct dlep_session *session) {
  memset(key, 0, sizeof(*key));
  if (dlep_reader_mac_tlv(key, session, NULL)) {
    OONF_INFO(session->log_source, "mac tlv missing");
    return -1;
  }

  if (dlep_reader_lid_tlv(key, session, NULL)) {
    OONF_DEBUG(session->log_source, "lid tlv not present");
  }
  else if (key->link_id_length != session->cfg.lid_length) {
    OONF_INFO(session->log_source, "LID TLV (length=%u) with bad length (should be %u)",
              key->link_id_length, session->cfg.lid_length);
    return -1;
  }
  return 0;
}

struct oonf_layer2_neigh *
dlep_extension_get_l2_neighbor(struct dlep_session *session) {
  struct oonf_layer2_net *l2net;

  struct oonf_layer2_neigh_key key;

  if (dlep_extension_get_l2_neighbor_key(&key, session)) {
    return NULL;
  }

  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (!l2net) {
    return NULL;
  }
  return oonf_layer2_neigh_get_lid(l2net, &key);
}

/**
 * Handle handle destination up/update for DLEP extension
 * by automatically mapping oonf_layer2_data to DLEP TLVs
 * @param ext dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
enum dlep_parser_error
dlep_extension_router_process_destination(struct dlep_extension *ext, struct dlep_session *session) {
  struct oonf_layer2_neigh *l2neigh;
  enum dlep_parser_error result;

  if (session->restrict_signal != DLEP_ALL_SIGNALS) {
    /* ignore unless we have an established session */
    return DLEP_NEW_PARSER_OKAY;
  }

  l2neigh = dlep_extension_get_l2_neighbor(session);
  if (!l2neigh) {
    return DLEP_NEW_PARSER_OKAY;
  }

  result = dlep_reader_map_l2neigh_data(l2neigh->data, session, ext);
  if (result) {
    OONF_INFO(session->log_source, "tlv mapping for extension %d failed: %d", ext->id, result);
    return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
  }
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Generate peer init ack for DLEP extension by automatically
 * mapping oonf_layer2_data to DLEP TLVs
 * @param ext dlep extension
 * @param session dlep session
 * @param neigh unused for this callback
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_extension_radio_write_session_init_ack(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh __attribute__((unused))) {
  const struct oonf_layer2_metadata *meta;
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_data *l2data;
  enum oonf_layer2_neighbor_index neigh_idx;
  enum oonf_layer2_network_index net_idx;
  size_t i;
  int result;

  /* first make sure defaults are set correctly */
  l2net = oonf_layer2_net_add(session->l2_listener.name);
  if (!l2net) {
    OONF_WARN(session->log_source, "Could not add l2net for new interface");
    return -1;
  }

  /* adding default neighbor data for mandatory values */
  for (i = 0; i < ext->neigh_mapping_count; i++) {
    if (!ext->neigh_mapping[i].mandatory) {
      continue;
    }

    neigh_idx = ext->neigh_mapping[i].layer2;
    l2data = &l2net->neighdata[neigh_idx];

    if (!oonf_layer2_data_has_value(l2data)) {
      meta = oonf_layer2_neigh_metadata_get(neigh_idx);
      oonf_layer2_data_set(l2data, session->l2_default_origin, meta, &ext->neigh_mapping[i].default_value);
    }
  }

  /* adding default interface data for mandatory values */
  for (i = 0; i < ext->if_mapping_count; i++) {
    if (!ext->if_mapping[i].mandatory) {
      continue;
    }

    net_idx = ext->if_mapping[i].layer2;
    l2data = &l2net->data[net_idx];

    if (!oonf_layer2_data_has_value(l2data)) {
      meta = oonf_layer2_net_metadata_get(net_idx);
      oonf_layer2_data_set(l2data, session->l2_default_origin, meta, &ext->if_mapping[i].default_value);
    }
  }

  /* write default metric values */
  OONF_DEBUG(session->log_source, "Mapping default neighbor data (%s) to TLVs", l2net->name);
  result = dlep_writer_map_l2neigh_data(&session->writer, ext, l2net->neighdata, NULL);
  if (result) {
    OONF_WARN(session->log_source, "tlv mapping for extension %d failed: %d", ext->id, result);
    return result;
  }

  /* write network wide data */
  OONF_DEBUG(session->log_source, "Mapping if data (%s) to TLVs", l2net->name);
  result = dlep_writer_map_l2net_data(&session->writer, ext, l2net->data);
  if (result) {
    OONF_WARN(session->log_source, "tlv mapping for extension %d failed: %d", ext->id, result);
    return result;
  }
  return 0;
}

/**
 * Generate peer update for DLEP extension by automatically
 * mapping oonf_layer2_data to DLEP TLVs
 * @param ext dlep extension
 * @param session dlep session
 * @param neigh unused for this callback
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_extension_radio_write_session_update(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh __attribute__((unused))) {
  struct oonf_layer2_net *l2net;
  int result;

  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (!l2net) {
    OONF_WARN(session->log_source, "Could not find l2net for new interface");
    return -1;
  }

  result = dlep_writer_map_l2neigh_data(&session->writer, ext, l2net->neighdata, NULL);
  if (result) {
    OONF_WARN(session->log_source, "tlv mapping for extension %d failed: %d", ext->id, result);
    return result;
  }

  result = dlep_writer_map_l2net_data(&session->writer, ext, l2net->data);
  if (result) {
    OONF_WARN(session->log_source, "tlv mapping for extension %d failed: %d", ext->id, result);
    return result;
  }
  return 0;
}

/**
 * Generate destination up/update for DLEP extension
 * by automatically mapping oonf_layer2_data to DLEP TLVs
 * @param ext dlep extension
 * @param session dlep session
 * @param neigh neighbor that should be updated
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_extension_radio_write_destination(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh) {
  struct oonf_layer2_neigh *l2neigh;
  union oonf_layer2_neigh_key_str nbuf;
  int result;

  l2neigh = dlep_session_get_local_l2_neighbor(session, neigh);
  if (!l2neigh) {
    OONF_WARN(session->log_source,
      "Could not find l2neigh "
      "for neighbor %s",
      oonf_layer2_neigh_key_to_string(&nbuf, neigh, true));
    return -1;
  }

  result = dlep_writer_map_l2neigh_data(&session->writer, ext, l2neigh->data, l2neigh->network->neighdata);
  if (result) {
    OONF_WARN(session->log_source,
      "tlv mapping for extension %d and neighbor %s failed: %d",
      ext->id, oonf_layer2_neigh_key_to_string(&nbuf, neigh, true), result);
    return result;
  }
  return 0;
}

/**
 * Handle peer update and session init ACK for DLEP extension
 * by automatically mapping oonf_layer2_data to DLEP TLVs
 * @param ext dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
static enum dlep_parser_error
_process_interface_specific_update(struct dlep_extension *ext, struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  int result;

  l2net = oonf_layer2_net_add(session->l2_listener.name);
  if (!l2net) {
    OONF_INFO(session->log_source, "Could not add l2net for new interface");
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }

  result = dlep_reader_map_l2neigh_data(l2net->neighdata, session, ext);
  if (result) {
    OONF_INFO(session->log_source, "tlv mapping for extension %d failed: %d", ext->id, result);
    return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
  }

  result = dlep_reader_map_l2net_data(l2net->data, session, ext);
  if (result) {
    OONF_INFO(session->log_source, "tlv mapping for extension %d failed: %d", ext->id, result);
    return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
  }
  return DLEP_NEW_PARSER_OKAY;
}
