
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

#ifndef _DLEP_EXTENSION_H_
#define _DLEP_EXTENSION_H_

struct dlep_extension;

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>

#include <oonf/base/oonf_layer2.h>

#include <oonf/generic/dlep/dlep_session.h>

/**
 * Extension for a specific DLEP signal
 */
struct dlep_extension_signal {
  /*! signal id */
  int32_t id;

  /*! array of supported tlv ids */
  const uint16_t *supported_tlvs;

  /*! number of supported tlv ids */
  size_t supported_tlv_count;

  /*! array of mandatory tlv ids */
  const uint16_t *mandatory_tlvs;

  /*! number of mandatory tlv ids */
  size_t mandatory_tlv_count;

  /*! array of tlvs that are allowed multiple times */
  const uint16_t *duplicate_tlvs;

  /*! number of tlvs that are allowed multiple times */
  size_t duplicate_tlv_count;

  /**
   * Callback for processing radio data
   * @param ext this dlep extension
   * @param session current dlep session
   * @return dlep error code
   */
  enum dlep_parser_error (*process_radio)(struct dlep_extension *ext, struct dlep_session *session);

  /**
   * Callback for processing router data
   * @param ext this dlep extension
   * @param session current dlep session
   * @return dlep error code
   */
  enum dlep_parser_error (*process_router)(struct dlep_extension *ext, struct dlep_session *session);

  /**
   * Callback to add TLVs to the extended radio signal
   * @param ext this dlep extension
   * @param session current dlep session
   * @param neigh neighbor used for this signal, might be NULL
   * @return -1 if an error happened, 0 otherwise
   */
  int (*add_radio_tlvs)(struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);

  /**
   * Callback to add TLVs to the extended router signal
   * @param ext this dlep extension
   * @param session current dlep session
   * @param neigh neighbor used for this signal, might be NULL
   * @return -1 if an error happened, 0 otherwise
   */
  int (*add_router_tlvs)(struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
};

/**
 * one TLV used by a DLEP extension
 */
struct dlep_extension_tlv {
  /*! tlv id */
  uint16_t id;

  /*! minimal length of tlv value */
  uint16_t length_min;

  /*! maximal length of tlv value */
  uint16_t length_max;
};

/**
 * implementation of a DLEP signal.
 *
 * This is used for extensions that must be split
 * into radio and router code. The dlep_extension_add_processing()
 * function will add the implementation to the callbacks in
 * dlep_extension_signal.
 */
struct dlep_extension_implementation {
  /*! extension id */
  int32_t id;

  /**
   * Callback for data processing
   * @param ext this dlep extension
   * @param session current dlep session
   * @return dlep error code
   */
  enum dlep_parser_error (*process)(struct dlep_extension *ext, struct dlep_session *session);

  /**
   * Callback to add TLVs to the extended signal
   * @param ext this dlep extension
   * @param session current dlep session
   * @param neigh neighbor used for this signal, might be NULL
   * @return -1 if an error happened, 0 otherwise
   */
  int (*add_tlvs)(struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
};

/**
 * Defines an mapping between a layer2_neighbor element and
 * a DLEP TLV
 */
struct dlep_neighbor_mapping {
  /*! dlep tlv id */
  uint16_t dlep;

  /*! binary length of tlv */
  uint16_t length;

  /* fixed integer arithmetics scaling factor */
  uint64_t scaling;

  /*! layer2 neighbor id */
  enum oonf_layer2_neighbor_index layer2;

  /*! layer2 neighbor id for DLEP to layer2 conversion (optional) */
  enum oonf_layer2_neighbor_index layer2_dst;

  /*! TLV is mandatory */
  bool mandatory;

  /*! default value for mandatory TLVs */
  union oonf_layer2_value default_value;

  /**
   * callback to transform a TLV into layer2 data
   * @param l2data layer2 data
   * @param meta metadata description for data
   * @param session dlep session
   * @param tlv tlv id
   * @param scaling fixed integer arithmetics scaling factor
   * @return -1 if an error happened, 0 otherwise
   */
  int (*from_tlv)(struct oonf_layer2_data *l2data, const struct oonf_layer2_metadata *meta,
    struct dlep_session *session, uint16_t tlv, uint64_t scaling);

  /**
   * callback to transform layer2 data into a DLEP tlv
   * @param writer dlep writer
   * @param l2data layer2 data
   * @param meta metadata description for data
   * @param tlv tlv id
   * @param length tlv length
   * @param scaling fixed integer arithmetics scaling factor
   * @return -1 if an error happened, 0 otherwise
   */
  int (*to_tlv)(struct dlep_writer *writer, struct oonf_layer2_data *l2data, const struct oonf_layer2_metadata *meta,
    uint16_t tlv, uint16_t length, uint64_t scaling);
};

/**
 * Defines an mapping between a layer2_network element and
 * a DLEP TLV
 */
struct dlep_network_mapping {
  /*! dlep tlv id */
  uint16_t dlep;

  /*! binary length of tlv */
  uint16_t length;

  /* fixed integer arithmetics scaling factor */
  uint64_t scaling;

  /*! layer2 network id */
  enum oonf_layer2_network_index layer2;

  /*! layer2 network id for DLEP to layer2 conversion (optional) */
  enum oonf_layer2_network_index layer2_dst;

  /*! TLV is mandatory */
  bool mandatory;

  /*! default value for mandatory TLVs */
  union oonf_layer2_value default_value;

  /**
   * callback to transform a TLV into layer2 data
   * @param l2data layer2 data
   * @param meta metadata description for data
   * @param session dlep session
   * @param tlv tlv id
   * @param scaling fixed integer arithmetics scaling factor
   * @return -1 if an error happened, 0 otherwise
   */
  int (*from_tlv)(struct oonf_layer2_data *l2data, const struct oonf_layer2_metadata *meta,
    struct dlep_session *session, uint16_t tlv, uint64_t scaling);

  /**
   * callback to transform layer2 data into a DLEP tlv
   * @param writer dlep writer
   * @param l2data layer2 data
   * @param meta metadata description for data
   * @param tlv tlv id
   * @param length tlv length
   * @param scaling fixed integer arithmetics scaling factor
   * @return -1 if an error happened, 0 otherwise
   */
  int (*to_tlv)(struct dlep_writer *writer, struct oonf_layer2_data *l2data, const struct oonf_layer2_metadata *meta,
    uint16_t tlv, uint16_t length, uint64_t scaling);
};

/**
 * definition of a DLEP extension
 */
struct dlep_extension {
  /*! id of dlep extension, -1 for base protocol */
  int id;

  /*! name of extension for debugging purpose */
  const char *name;

  /*! array of dlep signals used by this extension */
  struct dlep_extension_signal *signals;

  /*! number of dlep signals used by this extension */
  size_t signal_count;

  /*! array of dlep tlvs used by this extension */
  struct dlep_extension_tlv *tlvs;

  /*! number of dlep tlvs used by this extension */
  size_t tlv_count;

  /**
   * array of id mappings between DLEP tlvs
   * and oonf-layer2 neighbor data
   */
  struct dlep_neighbor_mapping *neigh_mapping;

  /*! number of id mappings for layer2 neighbor data */
  size_t neigh_mapping_count;

  /**
   * array of id mappings between DLEP tlvs
   * and oonf-layer2 network data
   */
  struct dlep_network_mapping *if_mapping;

  /*! number of id mappings for layer2 network data */
  size_t if_mapping_count;

  /**
   * Callback to initialize a new radio session
   * @param session dlep session
   */
  void (*cb_session_init_radio)(struct dlep_session *session);

  /**
   * Callback to initialize a new router session
   * @param session dlep session
   */
  void (*cb_session_init_router)(struct dlep_session *session);

  /**
   * Callback to apply new interface sessions to a new radio session
   * @param session dlep session
   */
  void (*cb_session_apply_radio)(struct dlep_session *session);

  /**
   * Callback to apply new interface sessions to a new router session
   * @param session dlep session
   */
  void (*cb_session_apply_router)(struct dlep_session *session);

  /**
   * Callback to deactivate an extension for a radio session
   * @param session dlep session
   */
  void (*cb_session_deactivate_radio)(struct dlep_session *session);

  /**
   * Callback to deactivate an extension for a router session
   * @param session dlep session
   */
  void (*cb_session_deactivate_router)(struct dlep_session *session);

  /**
   * Callback to cleanup all resources of a radio session
   * @param session dlep session
   */
  void (*cb_session_cleanup_radio)(struct dlep_session *session);

  /**
   * Callback to cleanup all resources of a router session
   * @param session dlep session
   */
  void (*cb_session_cleanup_router)(struct dlep_session *session);

  /*! node for global tree of extensions */
  struct avl_node _node;
};

EXPORT void dlep_extension_init(void);
EXPORT void dlep_extension_cleanup(void);

EXPORT void dlep_extension_add(struct dlep_extension *);
EXPORT struct avl_tree *dlep_extension_get_tree(void);
EXPORT void dlep_extension_add_processing(
  struct dlep_extension *, bool radio, struct dlep_extension_implementation *proc, size_t proc_count);
EXPORT const uint16_t *dlep_extension_get_ids(uint16_t *length);

EXPORT int dlep_extension_get_l2_neighbor_key(struct oonf_layer2_neigh_key *key, struct dlep_session *session);
EXPORT struct oonf_layer2_neigh *dlep_extension_get_l2_neighbor(struct dlep_session *session);

EXPORT enum dlep_parser_error dlep_extension_router_process_session_init_ack(struct dlep_extension *, struct dlep_session *session);
EXPORT enum dlep_parser_error dlep_extension_router_process_session_update(struct dlep_extension *, struct dlep_session *session);
EXPORT enum dlep_parser_error dlep_extension_router_process_destination(struct dlep_extension *, struct dlep_session *session);
EXPORT int dlep_extension_radio_write_session_init_ack(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
EXPORT int dlep_extension_radio_write_session_update(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);
EXPORT int dlep_extension_radio_write_destination(
  struct dlep_extension *ext, struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh);

/**
 * @param id dlep extension id
 * @return dlep extension, NULL if not found
 */
static INLINE struct dlep_extension *
dlep_extension_get(int32_t id) {
  struct dlep_extension *ext;
  return avl_find_element(dlep_extension_get_tree(), &id, ext, _node);
}

#endif /* _DLEP_EXTENSION_H_ */
