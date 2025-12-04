
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_reader.h>
#include <oonf/generic/dlep/dlep_writer.h>

#include <oonf/generic/dlep/ext_base_proto/proto.h>

static void _cb_local_heartbeat(struct oonf_timer_instance *);
static void _cb_remote_heartbeat(struct oonf_timer_instance *);

/* UDP peer discovery */

/* UDP peer offer */
static const uint16_t _peer_offer_tlvs[] = {
  DLEP_PEER_TYPE_TLV,
  DLEP_IPV4_CONPOINT_TLV,
  DLEP_IPV6_CONPOINT_TLV,
};

/* session initialization */
static const uint16_t _session_init_tlvs[] = {
  DLEP_HEARTBEAT_INTERVAL_TLV,
  DLEP_PEER_TYPE_TLV,
  DLEP_EXTENSIONS_SUPPORTED_TLV,
};
static const uint16_t _session_init_mandatory[] = {
  DLEP_HEARTBEAT_INTERVAL_TLV,
  DLEP_PEER_TYPE_TLV,
};

/* session initialization ack */
static const uint16_t _session_initack_tlvs[] = {
  DLEP_HEARTBEAT_INTERVAL_TLV,
  DLEP_STATUS_TLV,
  DLEP_PEER_TYPE_TLV,
  DLEP_EXTENSIONS_SUPPORTED_TLV,
};
static const uint16_t _session_initack_mandatory[] = {
  DLEP_HEARTBEAT_INTERVAL_TLV,
  DLEP_STATUS_TLV,
  DLEP_PEER_TYPE_TLV,
};

/* peer update */
static const uint16_t _peer_update_tlvs[] = {
  DLEP_STATUS_TLV,
};
static const uint16_t _peer_update_duplicates[] = {
  DLEP_STATUS_TLV,
};

/* peer update ack */
static const uint16_t _peer_updateack_tlvs[] = {
  DLEP_STATUS_TLV,
};
static const uint16_t _peer_updateack_mandatory[] = {
  DLEP_STATUS_TLV,
};

/* peer termination */
static const uint16_t _peer_termination_tlvs[] = {
  DLEP_STATUS_TLV,
};

/* peer termination ack */
static const uint16_t _peer_terminationack_tlvs[] = {
  DLEP_STATUS_TLV,
};

/* destination up */
static const uint16_t _dst_up_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
};
static const uint16_t _dst_up_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
};

/* destination up ack */
static const uint16_t _dst_up_ack_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
  DLEP_STATUS_TLV,
};
static const uint16_t _dst_up_ack_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
  DLEP_STATUS_TLV,
};

/* destination down */
static const uint16_t _dst_down_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
};
static const uint16_t _dst_down_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
};

/* destination down ack */
static const uint16_t _dst_down_ack_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
  DLEP_STATUS_TLV,
};
static const uint16_t _dst_down_ack_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
  DLEP_STATUS_TLV,
};

/* destination update */
static const uint16_t _dst_update_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
};
static const uint16_t _dst_update_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
};

/* link characteristics request */
static const uint16_t _linkchar_req_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
};
static const uint16_t _linkchar_req_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
};

/* link characteristics ack */
static const uint16_t _linkchar_ack_tlvs[] = {
  DLEP_MAC_ADDRESS_TLV,
  DLEP_STATUS_TLV,
};
static const uint16_t _linkchar_ack_mandatory[] = {
  DLEP_MAC_ADDRESS_TLV,
};

/* supported signals of this extension */
static struct dlep_extension_signal _signals[] = {
  {
    .id = DLEP_UDP_PEER_DISCOVERY,
  },
  {
    .id = DLEP_UDP_PEER_OFFER,
    .supported_tlvs = _peer_offer_tlvs,
    .supported_tlv_count = ARRAYSIZE(_peer_offer_tlvs),
  },
  {
    .id = DLEP_SESSION_INITIALIZATION,
    .supported_tlvs = _session_init_tlvs,
    .supported_tlv_count = ARRAYSIZE(_session_init_tlvs),
    .mandatory_tlvs = _session_init_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_session_init_mandatory),
  },
  {
    .id = DLEP_SESSION_INITIALIZATION_ACK,
    .supported_tlvs = _session_initack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_session_initack_tlvs),
    .mandatory_tlvs = _session_initack_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_session_initack_mandatory),
  },
  {
    .id = DLEP_SESSION_UPDATE,
    .supported_tlvs = _peer_update_tlvs,
    .supported_tlv_count = ARRAYSIZE(_peer_update_tlvs),
    .duplicate_tlvs = _peer_update_duplicates,
    .duplicate_tlv_count = ARRAYSIZE(_peer_update_duplicates),
  },
  {
    .id = DLEP_SESSION_UPDATE_ACK,
    .supported_tlvs = _peer_updateack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_peer_updateack_tlvs),
    .mandatory_tlvs = _peer_updateack_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_peer_updateack_mandatory),
  },
  {
    .id = DLEP_SESSION_TERMINATION,
    .supported_tlvs = _peer_termination_tlvs,
    .supported_tlv_count = ARRAYSIZE(_peer_termination_tlvs),
  },
  {
    .id = DLEP_SESSION_TERMINATION_ACK,
    .supported_tlvs = _peer_terminationack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_peer_terminationack_tlvs),
  },
  {
    .id = DLEP_DESTINATION_UP,
    .supported_tlvs = _dst_up_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_up_tlvs),
    .mandatory_tlvs = _dst_up_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_dst_up_mandatory),
  },
  {
    .id = DLEP_DESTINATION_UP_ACK,
    .supported_tlvs = _dst_up_ack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_up_ack_tlvs),
    .mandatory_tlvs = _dst_up_ack_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_dst_up_ack_mandatory),
  },
  {
    .id = DLEP_DESTINATION_DOWN,
    .supported_tlvs = _dst_down_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_down_tlvs),
    .mandatory_tlvs = _dst_down_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_dst_down_mandatory),
  },
  {
    .id = DLEP_DESTINATION_DOWN_ACK,
    .supported_tlvs = _dst_down_ack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_down_ack_tlvs),
    .mandatory_tlvs = _dst_down_ack_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_dst_down_ack_mandatory),
  },
  {
    .id = DLEP_DESTINATION_UPDATE,
    .supported_tlvs = _dst_update_tlvs,
    .supported_tlv_count = ARRAYSIZE(_dst_update_tlvs),
    .mandatory_tlvs = _dst_update_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_dst_update_mandatory),
  },
  {
    .id = DLEP_HEARTBEAT,
  },
  {
    .id = DLEP_LINK_CHARACTERISTICS_REQUEST,
    .supported_tlvs = _linkchar_req_tlvs,
    .supported_tlv_count = ARRAYSIZE(_linkchar_req_tlvs),
    .mandatory_tlvs = _linkchar_req_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_linkchar_req_mandatory),
  },
  {
    .id = DLEP_LINK_CHARACTERISTICS_ACK,
    .supported_tlvs = _linkchar_ack_tlvs,
    .supported_tlv_count = ARRAYSIZE(_linkchar_ack_tlvs),
    .mandatory_tlvs = _linkchar_ack_mandatory,
    .mandatory_tlv_count = ARRAYSIZE(_linkchar_ack_mandatory),
  },
};

/* supported TLVs of this extension */
static struct dlep_extension_tlv _tlvs[] = {
  { DLEP_STATUS_TLV, 1, 65535 },
  { DLEP_IPV4_CONPOINT_TLV, 5, 7 },
  { DLEP_IPV6_CONPOINT_TLV, 17, 19 },
  { DLEP_PEER_TYPE_TLV, 1, 255 },
  { DLEP_HEARTBEAT_INTERVAL_TLV, 4, 4 },
  { DLEP_EXTENSIONS_SUPPORTED_TLV, 2, 65534 },
  { DLEP_MAC_ADDRESS_TLV, 6, 8 },
  { DLEP_MDRR_TLV, 8, 8 },
  { DLEP_MDRT_TLV, 8, 8 },
  { DLEP_CDRR_TLV, 8, 8 },
  { DLEP_CDRT_TLV, 8, 8 },
  { DLEP_LATENCY_TLV, 8, 8 },
  { DLEP_RESOURCES_TLV, 1, 1 },
  { DLEP_RLQR_TLV, 1, 1 },
  { DLEP_RLQT_TLV, 1, 1 },
};

static struct dlep_neighbor_mapping _neigh_mappings[] = {
  {
    .dlep = DLEP_MDRR_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_MAX_BITRATE,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_MDRT_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_MAX_BITRATE,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CDRR_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_BITRATE,
    .length = 8,
    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_CDRT_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_BITRATE,
    .length = 8,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_LATENCY_TLV,
    .layer2 = OONF_LAYER2_NEIGH_LATENCY,
    .length = 8,
    .scaling = 1000000,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_RESOURCES_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RESOURCES,
    .length = 1,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_RLQR_TLV,
    .layer2 = OONF_LAYER2_NEIGH_RX_RLQ,
    .length = 1,
    .scaling = 1,

    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
  {
    .dlep = DLEP_RLQT_TLV,
    .layer2 = OONF_LAYER2_NEIGH_TX_RLQ,
    .length = 1,
    .from_tlv = dlep_reader_map_identity,
    .to_tlv = dlep_writer_map_identity,
  },
};

/* DLEP base extension, radio side */
static struct dlep_extension _base_proto = {
  .id = DLEP_EXTENSION_BASE_PROTO,
  .name = "base",

  .signals = _signals,
  .signal_count = ARRAYSIZE(_signals),
  .tlvs = _tlvs,
  .tlv_count = ARRAYSIZE(_tlvs),
  .neigh_mapping = _neigh_mappings,
  .neigh_mapping_count = ARRAYSIZE(_neigh_mappings),
};

static struct oonf_timer_class _local_heartbeat_class = {
  .name = "dlep local heartbeat",
  .callback = _cb_local_heartbeat,
  .periodic = true,
};
static struct oonf_timer_class _remote_heartbeat_class = {
  .name = "dlep remote heartbeat",
  .callback = _cb_remote_heartbeat,
};

/**
 * Get base protocol DLEP extension
 * @return this extension
 */
struct dlep_extension *
dlep_base_proto_init(void) {
  dlep_extension_add(&_base_proto);
  return &_base_proto;
}

/**
 * Start local heartbeat timer
 * @param session dlep session
 */
void
dlep_base_proto_start_local_heartbeat(struct dlep_session *session) {
  /* timer for local heartbeat generation */
  session->local_event_timer.class = &_local_heartbeat_class;
  oonf_timer_set(&session->local_event_timer, session->cfg.heartbeat_interval);
}

/**
 * Start remote heartbeat timer
 * @param session dlep session
 */
void
dlep_base_proto_start_remote_heartbeat(struct dlep_session *session) {
  /* timeout for remote heartbeats */
  session->remote_heartbeat_timeout.class = &_remote_heartbeat_class;
  oonf_timer_set(&session->remote_heartbeat_timeout, session->remote_heartbeat_interval * 2);
}

/**
 * Stop both heartbeat timers
 * @param session dlep session
 */
void
dlep_base_proto_stop_timers(struct dlep_session *session) {
  OONF_DEBUG(session->log_source, "Cleanup base session");
  oonf_timer_stop(&session->local_event_timer);
  oonf_timer_stop(&session->remote_heartbeat_timeout);
}

/**
 * Print content of the DLEP STATUS TLV to debug
 * @param session dlep session
 * @return dlep status
 */
enum dlep_status
dlep_base_proto_print_status(struct dlep_session *session)
{
  enum dlep_status status;
  char text[256];

  if (!dlep_reader_status(&status, text, sizeof(text), session, NULL)) {
    OONF_DEBUG(session->log_source, "Status %d received: %s", status, text);

    return status;
  }
  return DLEP_STATUS_OKAY;
}

/**
 * Print DLEP peer type to debug
 * @param session dlep session
 */
void
dlep_base_proto_print_peer_type(struct dlep_session *session) {
  char text[256];
  bool secure;

  if (!dlep_reader_peer_type(text, sizeof(text), &secure, session, NULL)) {
    OONF_DEBUG(session->log_source, "Remote peer type (%s): %s", secure ? "secure" : "open", text);
  }
}

/**
 * Process a DLEP peer termination message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_base_proto_process_session_termination(
  struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  dlep_base_proto_print_status(session);

  /* we can kill the session now */
  session->_peer_state = DLEP_PEER_TERMINATED;
  session->restrict_signal = DLEP_KILL_SESSION;

  /* ignore all signals we planned to send, only the Termination ACK is important now */
  abuf_clear(session->writer.out);

  /* generate Termination ACK */
  return dlep_session_generate_signal(session, DLEP_SESSION_TERMINATION_ACK, NULL);
}

/**
 * Process a DLEP peer termination ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_base_proto_process_session_termination_ack(
  struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  /* we can kill the session now */
  session->_peer_state = DLEP_PEER_TERMINATED;
  session->restrict_signal = DLEP_KILL_SESSION;

  /* don't send anything anymore */
  abuf_clear(session->writer.out);
  return 0;
}

/**
 * Process a DLEP heartbeat message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_base_proto_process_heartbeat(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  /* just restart the timeout with the same period */
  oonf_timer_set(&session->remote_heartbeat_timeout, session->remote_heartbeat_interval * 2);
  return 0;
}

/**
 * Write the mac address TLV into the DLEP message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @param neigh layer2 neighbor key to write into TLV
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_base_proto_write_mac_only(
  struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session, const struct oonf_layer2_neigh_key *neigh) {
  if (dlep_writer_add_mac_tlv(&session->writer, neigh)) {
    return -1;
  }
  return 0;
}

/**
 * Process the peer update message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_base_proto_process_session_update(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  struct oonf_layer2_net *l2net;
  int result;

  l2net = oonf_layer2_net_add(session->l2_listener.name);
  if (!l2net) {
    return DLEP_NEW_PARSER_OUT_OF_MEMORY;
  }

  if (!session->radio) {
    /* metric data is only transported radio to router */
    result = dlep_reader_map_l2neigh_data(l2net->neighdata, session, &_base_proto);
    if (result) {
      OONF_INFO(session->log_source, "tlv mapping failed for extension %u: %u", ext->id, result);
      return DLEP_NEW_PARSER_INTERNAL_ERROR;
    }
  }

  /* generate ACK */
  if (dlep_session_generate_signal_status(session, DLEP_SESSION_UPDATE_ACK, NULL, DLEP_STATUS_OKAY, "Success")) {
    return DLEP_NEW_PARSER_INTERNAL_ERROR;
  }
  dlep_base_proto_print_status(session);
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Process the peer update ack message
 * @param ext (this) dlep extension
 * @param session dlep session
 * @return always 0
 */
int
dlep_base_proto_process_session_update_ack(struct dlep_extension *ext __attribute__((unused)), struct dlep_session *session) {
  dlep_base_proto_print_status(session);
  if (session->_peer_state == DLEP_PEER_SEND_UPDATE) {
    if (dlep_session_generate_signal(session, DLEP_SESSION_UPDATE, NULL)) {
      // TODO: do we need to terminate here?
      return DLEP_NEW_PARSER_INTERNAL_ERROR;
    }
    session->_peer_state = DLEP_PEER_WAIT_FOR_UPDATE_ACK;
  }
  else {
    session->_peer_state = DLEP_PEER_IDLE;
  }
  dlep_base_proto_print_status(session);
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Callback triggered when to generate a new heartbeat
 * @param ptr timer instance that fired
 */
static void
_cb_local_heartbeat(struct oonf_timer_instance *ptr) {
  struct dlep_session *session;

  session = container_of(ptr, struct dlep_session, local_event_timer);

  dlep_session_generate_signal(session, DLEP_HEARTBEAT, NULL);
  session->cb_send_buffer(session, 0);
}

/**
 * Callback triggered when the remote heartbeat times out
 * @param ptr timer instance that fired
 */
static void
_cb_remote_heartbeat(struct oonf_timer_instance *ptr) {
  struct dlep_session *session;

  session = container_of(ptr, struct dlep_session, remote_heartbeat_timeout);

  if (session->restrict_signal == DLEP_SESSION_TERMINATION_ACK) {
    /* peer termination ACK is missing! */

    /* stop local heartbeats */
    oonf_timer_stop(&session->local_event_timer);

    /* hard-terminate session */
    if (session->cb_end_session) {
      session->cb_end_session(session);
    }
  }
  else {
    /* soft-terminate session (send PEER_TERM) */
    dlep_session_terminate(session, DLEP_STATUS_TIMED_OUT, "Remote heartbeat timed out");

    /* set timeout for hard-termination */
    oonf_timer_set(&session->remote_heartbeat_timeout, session->remote_heartbeat_interval * 2);
  }
}
