
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
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_session.h>
#include <oonf/generic/dlep/dlep_writer.h>

/**
 * internal constants of DLEP session
 */
enum
{
  /*! size increase step for DLEP value storage */
  SESSION_VALUE_STEP = 128,
};

static int _update_allowed_tlvs(struct dlep_session *session);
static enum dlep_parser_error _parse_tlvstream(struct dlep_session *session, const uint8_t *buffer, size_t length);
static enum dlep_parser_error _check_mandatory(
  struct dlep_session *session, struct dlep_extension *ext, int32_t signal_type);
static enum dlep_parser_error _check_duplicate(
  struct dlep_session *session, struct dlep_extension *ext, int32_t signal_type);
static enum dlep_parser_error _call_extension_processing(
  struct dlep_session *parser, struct dlep_extension *ext, int32_t signal_type);
static struct dlep_parser_tlv *_add_session_tlv(struct dlep_session_parser *parser, uint16_t id);
static enum dlep_parser_error _handle_extension(
  struct dlep_session *session, struct dlep_extension *ext, uint32_t signal_type);
static enum dlep_parser_error _process_tlvs(
  struct dlep_session *, int32_t signal_type, uint16_t signal_length, const uint8_t *tlvs);
static void _send_terminate(struct dlep_session *session, enum dlep_status status, const char *status_text);
static void _cb_destination_timeout(struct oonf_timer_instance *);

static struct oonf_class _tlv_class = {
  .name = "dlep reader tlv",
  .size = sizeof(struct dlep_parser_tlv),
};

static struct oonf_class _local_neighbor_class = {
  .name = "dlep neighbor",
  .size = sizeof(struct dlep_local_neighbor),
};

static struct oonf_timer_class _destination_ack_class = {
  .name = "dlep destination ack",
  .callback = _cb_destination_timeout,
};

/**
 * Initialize DLEP session system
 */
void
dlep_session_init(void) {
  oonf_class_add(&_tlv_class);
  oonf_class_add(&_local_neighbor_class);
  oonf_timer_add(&_destination_ack_class);
}

/**
 * Initialize a session, will hook in the base extension
 * @param session session to initialize
 * @param l2_ifname name of layer2 interface for dlep session
 * @param l2_origin layer2 db origin id for session
 * @param l2_default_origin layer2 originator that shall be used for setting defaults
 * @param out output buffer for session
 * @param radio true if this is a radio session,
 *   false for a router session
 * @param if_changed interface listener for session, can be NULL
 * @param log_source logging source for session
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_session_add(struct dlep_session *session, const char *l2_ifname, const struct oonf_layer2_origin *l2_origin,
  const struct oonf_layer2_origin *l2_default_origin, struct autobuf *out, bool radio,
  int (*if_changed)(struct os_interface_listener *), enum oonf_log_source log_source) {
  struct dlep_session_parser *parser;
  struct dlep_extension *ext;

  parser = &session->parser;

  avl_init(&parser->allowed_tlvs, avl_comp_uint16, false);
  avl_init(&session->local_neighbor_tree, oonf_layer2_avlcmp_neigh_key, false);

  session->log_source = log_source;
  session->l2_origin = l2_origin;
  session->l2_default_origin = l2_default_origin;
  session->radio = radio;
  session->writer.out = out;
  session->_peer_state = DLEP_PEER_WAIT_FOR_INIT;

  /* remember interface name */
  session->l2_listener.name = l2_ifname;
  session->l2_listener.if_changed = if_changed;

  /* get interface listener to lock interface */
  if (!os_interface_add(&session->l2_listener)) {
    OONF_WARN(session->log_source, "Cannot activate interface listener for %s", l2_ifname);
    dlep_session_remove(session);
    return -1;
  }

  parser->values = calloc(SESSION_VALUE_STEP, sizeof(struct dlep_parser_value));
  if (!parser->values) {
    OONF_WARN(session->log_source, "Cannot allocate values buffer for %s", l2_ifname);
    dlep_session_remove(session);
    return -1;
  }

  /* generate full list of extensions */
  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    OONF_DEBUG(session->log_source, "Add extension %d to session", ext->id);
    parser->extensions[parser->extension_count] = ext;
    parser->extension_count++;
  }

  if (_update_allowed_tlvs(session)) {
    OONF_WARN(session->log_source, "Could not update allowed TLVs for %s", l2_ifname);
    dlep_session_remove(session);
    return -1;
  }

  avl_init(&session->_ext_ip.prefix_modification, avl_comp_netaddr, false);
  session->activation_time = oonf_clock_getNow();

  OONF_INFO(session->log_source, "Add session on %s", session->l2_listener.name);
  return 0;
}

/**
 * Remove a DLEP session
 * @param session dlep session
 */
void
dlep_session_remove(struct dlep_session *session) {
  struct dlep_parser_tlv *tlv, *tlv_it;
  struct dlep_session_parser *parser;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  OONF_DEBUG(session->log_source, "Remove session if %s to %s", session->l2_listener.name,
    netaddr_socket_to_string(&nbuf, &session->remote_socket));

  netaddr_socket_invalidate(&session->local_socket);
  netaddr_socket_invalidate(&session->remote_socket);

  os_interface_remove(&session->l2_listener);

  parser = &session->parser;
  avl_for_each_element_safe(&parser->allowed_tlvs, tlv, _node, tlv_it) {
    avl_remove(&parser->allowed_tlvs, &tlv->_node);
    oonf_class_free(&_tlv_class, tlv);
  }

  oonf_timer_stop(&session->local_event_timer);
  oonf_timer_stop(&session->remote_heartbeat_timeout);

  parser->extension_count = 0;

  free(parser->values);
  parser->values = NULL;

  session->_peer_state = DLEP_PEER_NOT_CONNECTED;
}

/**
 * Send peer termination
 * @param session dlep session
 * @param status DLEP status code for termination
 * @param status_text text message for termination
 */
void
dlep_session_terminate(struct dlep_session *session, enum dlep_status status, const char *status_text) {
  if (session->restrict_signal != DLEP_ALL_SIGNALS) {
    dlep_session_generate_signal_status(session, DLEP_SESSION_TERMINATION, NULL, status, status_text);
    session->cb_send_buffer(session, 0);
  }
  session->restrict_signal = DLEP_SESSION_TERMINATION_ACK;
}

/**
 * Update the list of active dlep extensions for a session
 * @param session dlep session
 * @param extvalues array with allowed DLEP sessions
 * @param extcount number of bytes in array
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_session_update_extensions(struct dlep_session *session, const uint8_t *extvalues, size_t extcount, bool radio) {
  struct dlep_extension *ext;
  size_t i, j;
  bool deactivate;
  uint16_t extid;
  OONF_INFO(session->log_source, "Update session extension list");

  /* deactivate all extensions not present anymore  */
  for (j = DLEP_EXTENSION_BASE_COUNT; j < session->parser.extension_count; j++) {
    deactivate = true;

    for (i = 0; i < extcount; i++) {
      memcpy(&extid, &extvalues[i * 2], sizeof(extid));
      if (ntohs(extid) == session->parser.extensions[j]->id) {
        deactivate = false;
        break;
      }
    }

    if (deactivate) {
      if (radio) {
        session->parser.extensions[j]->cb_session_deactivate_radio(session);
      }
      else {
        session->parser.extensions[j]->cb_session_deactivate_router(session);
      }
    }
  }

  /* generate new session extension list */
  session->parser.extension_count = DLEP_EXTENSION_BASE_COUNT;
  for (i = 0; i < extcount; i++) {
    memcpy(&extid, &extvalues[i * 2], sizeof(extid));

    ext = dlep_extension_get(ntohs(extid));
    if (ext) {
      OONF_INFO(session->log_source, "Add extension: %d", ntohs(extid));

      session->parser.extensions[session->parser.extension_count] = ext;
      session->parser.extension_count++;
    }
  }
  return _update_allowed_tlvs(session);
}

/**
 * Process data in DLEP session TCP input buffer
 * @param tcp_session TCP session
 * @param session DLEP session
 * @return new TCP session state
 */
enum oonf_stream_session_state
dlep_session_process_tcp(struct oonf_stream_session *tcp_session, struct dlep_session *session)
{
  ssize_t processed;

  OONF_DEBUG(
    session->log_source, "Process TCP buffer of %" PRINTF_SIZE_T_SPECIFIER " bytes", abuf_getlen(&tcp_session->in));

  processed = dlep_session_process_buffer(session, abuf_getptr(&tcp_session->in), abuf_getlen(&tcp_session->in), false);

  if (processed < 0) {
    /* session is most likely invalid now */
    return STREAM_SESSION_CLEANUP;
  }

  if (session->restrict_signal == DLEP_KILL_SESSION) {
    return STREAM_SESSION_CLEANUP;
  }

  OONF_DEBUG(session->log_source, "Processed %" PRINTF_SSIZE_T_SPECIFIER " bytes", processed);

  abuf_pull(&tcp_session->in, processed);

  if (abuf_getlen(session->writer.out) > 0) {
    OONF_DEBUG(
      session->log_source, "Trigger sending %" PRINTF_SIZE_T_SPECIFIER " bytes", abuf_getlen(session->writer.out));

    /* send answer */
    oonf_stream_flush(tcp_session);
  }

  if (session->restrict_signal == DLEP_KILL_SESSION) {
    return STREAM_SESSION_CLEANUP;
  }
  return STREAM_SESSION_ACTIVE;
}

/**
 * Process the content of a buffer as DLEP signal(s)
 * @param session dlep session
 * @param buffer pointer to buffer
 * @param length length of buffer
 * @return number of bytes of buffer which were parsed and
 *   can be removed, -1 if an error happened
 */
ssize_t
dlep_session_process_buffer(struct dlep_session *session, const void *buffer, size_t length, bool is_udp) {
  ssize_t result, offset;
  const char *ptr;

  offset = 0;
  ptr = buffer;

  OONF_DEBUG(session->log_source,
    "Processing buffer of"
    " %" PRINTF_SIZE_T_SPECIFIER " bytes",
    length);
  while (length > 0) {
    OONF_DEBUG(session->log_source,
      "Processing message at offset"
      " %" PRINTF_SSIZE_T_SPECIFIER,
      offset);

    if ((result = dlep_session_process_signal(session, &ptr[offset], length, is_udp)) <= 0) {
      if (result < 0) {
        return result;
      }
      break;
    }

    if (session->restrict_signal == DLEP_KILL_SESSION) {
      return offset;
    }
    length -= result;
    offset += result;
  }
  return offset;
}

/**
 * Process a DLEP signal/message
 * @param session dlep session
 * @param ptr pointer to buffer with DLEP signal/message
 * @param length length of buffer
 * @return number of bytes parsed, 0 if a generic error happened,
 *   negative to return a parser result enum
 */
ssize_t
dlep_session_process_signal(struct dlep_session *session, const void *ptr, size_t length, bool is_udp) {
  enum dlep_parser_error result;
  uint16_t original_signal_type;
  int32_t signal_type;
  uint16_t signal_length;
  const uint8_t *buffer;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  session->next_restrict_signal = DLEP_KEEP_RESTRICTION;

  if (length < 4) {
    /* not enough data for a signal type */
    OONF_DEBUG(session->log_source,
      "Not enough data to process"
      " signal from %s (%" PRINTF_SIZE_T_SPECIFIER " bytes)",
      netaddr_socket_to_string(&nbuf, &session->remote_socket), length);

    return 0;
  }

  buffer = ptr;

  /* copy data */
  memcpy(&original_signal_type, &buffer[0], sizeof(original_signal_type));
  memcpy(&signal_length, &buffer[2], sizeof(signal_length));
  signal_type = ntohs(original_signal_type);
  signal_length = ntohs(signal_length);

  if (is_udp) {
    signal_type += DLEP_IS_UDP_SIGNAL;
  }

  if (length < (size_t)signal_length + 4u) {
    /* not enough data for signal */
    OONF_DEBUG(session->log_source,
      "Not enough data to process"
      " signal %u (length %u) from %s"
      " (%" PRINTF_SIZE_T_SPECIFIER " bytes)",
      signal_type, signal_length, netaddr_socket_to_string(&nbuf, &session->remote_socket), length);
    return 0;
  }

  OONF_DEBUG_HEX(session->log_source, buffer, signal_length + 4,
    "Process signal %d from %s (%" PRINTF_SIZE_T_SPECIFIER " bytes)", signal_type,
    netaddr_socket_to_string(&nbuf, &session->remote_socket), length);

  if (session->restrict_signal != DLEP_ALL_SIGNALS && session->restrict_signal != signal_type) {
    OONF_DEBUG(session->log_source,
      "Signal should have been %d,"
      " drop session",
      session->restrict_signal);
    /* we only accept a single type and we got the wrong one */
    return -1;
  }

  result = _process_tlvs(session, signal_type, signal_length, &buffer[4]);

  if (result == DLEP_NEW_PARSER_TERMINDATED) {
    /* session is now invalid, end parser */
    return result;
  }
  if (result != DLEP_NEW_PARSER_OKAY) {
    OONF_WARN(session->log_source, "Parser error: %d", result);
    _send_terminate(session, DLEP_STATUS_INVALID_DATA, "Incoming signal could not be parsed");
  }
  else if (session->next_restrict_signal != DLEP_KEEP_RESTRICTION) {
    session->restrict_signal = session->next_restrict_signal;
  }

  /* skip forward */
  return signal_length + 4;
}

/**
 * Add a neighbor to the local DLEP storage
 * @param session dlep session
 * @param key neighbor key (MAC plus link id)
 * @return pointer to dlep neighbor, NULL if out of memory
 */
struct dlep_local_neighbor *
dlep_session_add_local_neighbor(struct dlep_session *session, const struct oonf_layer2_neigh_key *key) {
  struct dlep_local_neighbor *local;
  if ((local = dlep_session_get_local_neighbor(session, key))) {
    return local;
  }

  if (key->link_id_length != 0 && key->link_id_length != session->cfg.lid_length) {
    /* LIDs not allowed */
    return NULL;
  }
  local = oonf_class_malloc(&_local_neighbor_class);
  if (!local) {
    return NULL;
  }

  /* hook into tree */
  memcpy(&local->key, key, sizeof(*key));
  local->_node.key = &local->key;
  avl_insert(&session->local_neighbor_tree, &local->_node);

  /* initialize timer */
  local->_ack_timeout.class = &_destination_ack_class;

  /* initialize backpointer */
  local->session = session;

  avl_init(&local->_ip_prefix_modification, avl_comp_netaddr, false);

  return local;
}

/**
 * Remove a neighbor from the DLEP storage
 * @param session dlep session
 * @param local DLEP neighbor
 */
void
dlep_session_remove_local_neighbor(struct dlep_session *session, struct dlep_local_neighbor *local) {
  avl_remove(&session->local_neighbor_tree, &local->_node);
  oonf_timer_stop(&local->_ack_timeout);
  oonf_class_free(&_local_neighbor_class, local);
}

/**
 * Get the layer2 neigbor for a DLEP session MAC address
 * @param session dlep session
 * @param key neighbor key (MAC address plus link id)
 * @return layer2 neighbor, NULL if not found
 */
struct oonf_layer2_neigh *
dlep_session_get_local_l2_neighbor(struct dlep_session *session, const struct oonf_layer2_neigh_key *key) {
  struct dlep_local_neighbor *dlep_neigh;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_net *l2net;
#ifdef OONF_LOG_INFO
  union oonf_layer2_neigh_key_str nbuf1, nbuf2;
#endif

  dlep_neigh = dlep_session_get_local_neighbor(session, key);
  if (!dlep_neigh) {
    OONF_INFO(session->log_source, "Could not find local neighbor for %s",
              oonf_layer2_neigh_key_to_string(&nbuf1, key, true));
    return NULL;
  }

  l2net = oonf_layer2_net_get(session->l2_listener.name);
  if (!l2net) {
    OONF_DEBUG(session->log_source, "Could not find l2net %s for new neighbor", session->l2_listener.name);
    return NULL;
  }

  l2neigh = oonf_layer2_neigh_get_lid(l2net, &dlep_neigh->neigh_key);
  if (!l2neigh) {
    OONF_INFO(session->log_source,
      "Could not find l2neigh for neighbor %s (%s)",
      oonf_layer2_neigh_key_to_string(&nbuf1, key, true),
      oonf_layer2_neigh_key_to_string(&nbuf2, &dlep_neigh->neigh_key, true));
    return NULL;
  }
  return l2neigh;
}

struct oonf_layer2_neigh *
dlep_session_get_l2_from_neighbor(struct dlep_local_neighbor *dlep_neigh) {
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_net *l2net;
#ifdef OONF_LOG_INFO
  union oonf_layer2_neigh_key_str nbuf;
#endif

  l2net = oonf_layer2_net_get(dlep_neigh->session->l2_listener.name);
  if (!l2net) {
    OONF_DEBUG(dlep_neigh->session->log_source, "Could not find l2net %s for new neighbor",
      dlep_neigh->session->l2_listener.name);
    return NULL;
  }

  l2neigh = oonf_layer2_neigh_get_lid(l2net, &dlep_neigh->neigh_key);
  if (!l2neigh) {
    OONF_INFO(dlep_neigh->session->log_source,
      "Could not find l2neigh for neighbor %s",
      oonf_layer2_neigh_key_to_string(&nbuf, &dlep_neigh->neigh_key, true));
    return NULL;
  }
  return l2neigh;
}

/**
 * Generate a DLEP signal/message
 * @param session dlep session
 * @param signal signal id
 * @param neighbor neighbor MAC address the signal should refer to,
 *   might be NULL
 * @return -1 if an error happened, 0 otherwise
 */
static int
_generate_signal(struct dlep_session *session, int32_t signal, const struct oonf_layer2_neigh_key *neighbor) {
  struct dlep_extension *ext;
  size_t e, s;

  size_t len;
#ifdef OONF_LOG_DEBUG_INFO
  union oonf_layer2_neigh_key_str nkbuf;
  struct netaddr_str nbuf2;
#endif

  OONF_DEBUG(session->log_source, "Generate signal %u for %s on %s (0x%zx %s)", signal,
             oonf_layer2_neigh_key_to_string(&nkbuf, neighbor, true),
             session->l2_listener.name, (size_t)session, netaddr_socket_to_string(&nbuf2, &session->remote_socket));

  len = abuf_getlen(session->writer.out);

  /* generate signal, mask out UDP/TCP difference */
  dlep_writer_start_signal(&session->writer, signal & 65535);
  for (e = 0; e < session->parser.extension_count; e++) {
    ext = session->parser.extensions[e];

    for (s = 0; s < ext->signal_count; s++) {
      if (ext->signals[s].id != signal) {
        continue;
      }

      if (session->radio && ext->signals[s].add_radio_tlvs) {
        OONF_DEBUG(session->log_source, "Add tlvs for radio extension %d", ext->id);
        if (ext->signals[s].add_radio_tlvs(ext, session, neighbor)) {
          abuf_setlen(session->writer.out, len);
          return -1;
        }
      }
      else if (!session->radio && ext->signals[s].add_router_tlvs) {
        OONF_DEBUG(session->log_source, "Add tlvs for router extension %d", ext->id);
        if (ext->signals[s].add_router_tlvs(ext, session, neighbor)) {
          abuf_setlen(session->writer.out, len);
          return -1;
        }
      }
      break;
    }
  }

  OONF_DEBUG(
    session->log_source, "generated %" PRINTF_SIZE_T_SPECIFIER " bytes", abuf_getlen(session->writer.out) - len);
  return 0;
}

/**
 * Generate a DLEP signal/message
 * @param session dlep session
 * @param signal signal id
 * @param neighbor neighbor MAC address (plus link id) the signal should refer to,
 *   might be NULL
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_session_generate_signal(struct dlep_session *session, int32_t signal, const struct oonf_layer2_neigh_key *neighbor) {
  if (_generate_signal(session, signal, neighbor)) {
    OONF_WARN(session->log_source, "Could not generate signal %u", signal);
    return -1;
  }
  return dlep_writer_finish_signal(&session->writer, session->log_source);
}

/**
 * Generate a DLEP signal/message with a DLEP status TLV
 * @param session dlep session
 * @param signal signal id
 * @param neighbor neighbor MAC address (plus link id) the signal should refer to,
 *   might be NULL
 * @param status DLEP status code
 * @param msg ZERO terminated DLEP status text
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_session_generate_signal_status(struct dlep_session *session, int32_t signal, const struct oonf_layer2_neigh_key *neighbor,
  enum dlep_status status, const char *msg) {
  if (_generate_signal(session, signal, neighbor)) {
    OONF_WARN(session->log_source, "Could not generate signal %u", signal);
    return -1;
  }
  if (dlep_writer_add_status(&session->writer, status, msg)) {
    OONF_WARN(session->log_source, "Could not add status TLV");
    return -1;
  }
  return dlep_writer_finish_signal(&session->writer, session->log_source);
}

/**
 * Get the value of the first DLEP TLV of a specific type
 * @param session dlep session
 * @param tlvtype DLEP TLV type
 * @return DLEP value, NULL if not found
 */
struct dlep_parser_value *
dlep_session_get_tlv_value(struct dlep_session *session, uint16_t tlvtype) {
  struct dlep_parser_tlv *tlv;
  struct dlep_parser_value *value;

  tlv = dlep_parser_get_tlv(&session->parser, tlvtype);
  if (!tlv) {
    OONF_INFO(session->log_source, "Could not find TLV type %u", tlvtype);
    return NULL;
  }

  value = dlep_session_get_tlv_first_value(session, tlv);
  if (!value) {
    OONF_INFO(session->log_source, "Could not find value of TLV type %u", tlvtype);
    return NULL;
  }
  else {
    OONF_DEBUG(session->log_source, "TLV %u has value", tlvtype);
  }
  return value;
}

/**
 * Update the list of allowed TLVs based on the list of allowed
 * extensions
 * @param session dlep session
 * @return -1 if extensions are inconsistent, 0 otherwise
 */
static int
_update_allowed_tlvs(struct dlep_session *session) {
  struct dlep_session_parser *parser;
  struct dlep_parser_tlv *tlv, *tlv_it;
  struct dlep_extension *ext;
  size_t e, t;
  uint16_t id;

  parser = &session->parser;

  /* mark all existing allowed tlvs */
  avl_for_each_element_safe(&parser->allowed_tlvs, tlv, _node, tlv_it) {
    tlv->remove = true;
  }

  /* allocate new allowed tlvs structures */
  for (e = 0; e < parser->extension_count; e++) {
    ext = parser->extensions[e];

    /* for all extensions */
    for (t = 0; t < ext->tlv_count; t++) {
      /* for all tlvs */
      id = ext->tlvs[t].id;
      tlv = dlep_parser_get_tlv(parser, id);
      if (!tlv) {
        /* new tlv found! */
        if (!(tlv = _add_session_tlv(parser, id))) {
          return -1;
        }
        tlv->length_min = ext->tlvs[t].length_min;
        tlv->length_max = ext->tlvs[t].length_max;
      }
      else if (tlv->length_min != ext->tlvs[t].length_min || tlv->length_max != ext->tlvs[t].length_max) {
        OONF_WARN(session->log_source,
          "Two extensions conflict about"
          " tlv %u minimal/maximum length",
          id);
        return -1;
      }

      tlv->remove = false;
    }
  }

  /* remove all existing allowed tlvs that are not supported anymore */
  avl_for_each_element_safe(&parser->allowed_tlvs, tlv, _node, tlv_it) {
    if (tlv->remove) {
      avl_remove(&parser->allowed_tlvs, &tlv->_node);
      oonf_class_free(&_tlv_class, tlv);
    }
  }

  return 0;
}

/**
 * Check constraints of extensions and call the relevant callbacks
 * @param session dlep session
 * @param ext dlep extension
 * @param signal_type signal type
 * @return dlep parser error, 0 of everything is fine
 */
static enum dlep_parser_error
_handle_extension(struct dlep_session *session, struct dlep_extension *ext, uint32_t signal_type) {
  enum dlep_parser_error result;
  bool active;
  size_t e;

  active = false;

  /* only handle active extensions */
  for (e = 0; e < session->parser.extension_count; e++) {
    if (session->parser.extensions[e] == ext) {
      active = true;
      break;
    }
  }
  if (!active) {
    /* not active at the moment */
    return DLEP_NEW_PARSER_OKAY;
  }

  if ((result = _check_mandatory(session, ext, signal_type))) {
    OONF_DEBUG(session->log_source, "check_mandatory result: %d", result);
    return result;
  }
  if ((result = _check_duplicate(session, ext, signal_type))) {
    OONF_DEBUG(session->log_source, "check_duplicate result: %d", result);
    return result;
  }

  if ((result = _call_extension_processing(session, ext, signal_type))) {
    OONF_DEBUG(session->log_source, "extension processing failed: %d", result);
    return result;
  }

  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Parse a DLEP tlv
 * @param session dlep session
 * @param signal_type dlep signal/message type
 * @param signal_length signal/message length
 * @param tlvs pointer to bytearray with TLVs
 * @return dlep parser status
 */
static enum dlep_parser_error
_process_tlvs(struct dlep_session *session, int32_t signal_type, uint16_t signal_length, const uint8_t *tlvs) {
  enum dlep_parser_error result;
  struct dlep_extension *ext;

  /* start at the beginning of the tlvs */
  if ((result = _parse_tlvstream(session, tlvs, signal_length))) {
    OONF_DEBUG(session->log_source, "parse_tlvstream result: %d", result);
    return result;
  }

  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if ((result = _handle_extension(session, ext, signal_type))) {
      return result;
    }
  }

  return DLEP_NEW_PARSER_OKAY;
}

/**
 * terminate a DLEP session
 * @param session dlep session
 * @param status DLEP status code for termination
 * @param status_text text message for termination
 */
static void
_send_terminate(struct dlep_session *session, enum dlep_status status, const char *status_text) {
  if (session->restrict_signal != DLEP_UDP_PEER_DISCOVERY && session->restrict_signal != DLEP_UDP_PEER_OFFER) {
    dlep_session_generate_signal_status(session, DLEP_SESSION_TERMINATION, NULL, status, status_text);

    session->restrict_signal = DLEP_SESSION_TERMINATION_ACK;
    session->next_restrict_signal = DLEP_SESSION_TERMINATION_ACK;
  }
}

/**
 * Callback when a destination up/down signal times out
 * @param ptr timer instance that fired
 */
static void
_cb_destination_timeout(struct oonf_timer_instance *ptr) {
  struct dlep_local_neighbor *local;

  local = container_of(ptr, struct dlep_local_neighbor, _ack_timeout);
  if (local->session->cb_destination_timeout) {
    local->session->cb_destination_timeout(local->session, local);
  }
}

/**
 * parse a stream of DLEP tlvs
 * @param session dlep session
 * @param buffer TLV buffer
 * @param length buffer size
 * @return DLEP parser status
 */
static enum dlep_parser_error
_parse_tlvstream(struct dlep_session *session, const uint8_t *buffer, size_t length) {
  struct dlep_session_parser *parser;
  struct dlep_parser_tlv *tlv;
  struct dlep_parser_value *value;
  uint16_t tlv_type;
  uint16_t tlv_length;
  size_t tlv_count, idx;

  parser = &session->parser;
  parser->tlv_ptr = buffer;
  tlv_count = 0;
  idx = 0;

  avl_for_each_element(&parser->allowed_tlvs, tlv, _node) {
    tlv->tlv_first = -1;
    tlv->tlv_last = -1;
  }

  while (idx < length) {
    if (length - idx < 4) {
      /* too short for a TLV, end parsing */
      return DLEP_NEW_PARSER_INCOMPLETE_TLV_HEADER;
    }

    /* copy header */
    memcpy(&tlv_type, &buffer[idx], sizeof(tlv_type));
    idx += sizeof(tlv_type);
    tlv_type = ntohs(tlv_type);

    memcpy(&tlv_length, &buffer[idx], sizeof(tlv_length));
    idx += sizeof(tlv_length);
    tlv_length = ntohs(tlv_length);

    if (idx + tlv_length > length) {
      OONF_WARN(session->log_source,
        "TLV %u incomplete: "
        "%" PRINTF_SIZE_T_SPECIFIER " > %" PRINTF_SIZE_T_SPECIFIER,
        tlv_type, idx + tlv_length, length);
      return DLEP_NEW_PARSER_INCOMPLETE_TLV;
    }

    /* check if tlv is supported */
    tlv = dlep_parser_get_tlv(parser, tlv_type);
    if (!tlv) {
      OONF_INFO(session->log_source, "Unsupported TLV %u", tlv_type);
      return DLEP_NEW_PARSER_UNSUPPORTED_TLV;
    }

    /* check length */
    if (tlv->length_max < tlv_length || tlv->length_min > tlv_length) {
      OONF_WARN(session->log_source,
        "TLV %u has wrong size,"
        " %d is not between %u and %u",
        tlv_type, tlv_length, tlv->length_min, tlv->length_max);
      return DLEP_NEW_PARSER_ILLEGAL_TLV_LENGTH;
    }

    /* check if we need to allocate more space for value pointers */
    if (parser->value_max_count == tlv_count) {
      /* allocate more */
      value = realloc(parser->values, sizeof(*value) * (tlv_count + SESSION_VALUE_STEP));
      if (!value) {
        return DLEP_NEW_PARSER_OUT_OF_MEMORY;
      }
      parser->value_max_count += SESSION_VALUE_STEP;
      parser->values = value;
    }

    OONF_DEBUG_HEX(session->log_source, &buffer[idx], tlv_length, "Received TLV %u", tlv_type);

    /* remember tlv value */
    value = &parser->values[tlv_count];
    value->tlv_next = -1;
    value->index = idx;
    value->length = tlv_length;

    if (tlv->tlv_last == -1) {
      /* first tlv */
      tlv->tlv_first = tlv_count;
    }
    else {
      /* one more */
      value = &parser->values[tlv->tlv_last];
      value->tlv_next = tlv_count;
    }
    tlv->tlv_last = tlv_count;
    tlv_count++;

    idx += tlv_length;
  }

  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Check if all mandatory TLVs were found
 * @param session dlep session
 * @param ext dlep extension
 * @param signal_type dlep signal/message type
 * @return dlep parser status
 */
static enum dlep_parser_error
_check_mandatory(struct dlep_session *session, struct dlep_extension *ext, int32_t signal_type) {
  struct dlep_session_parser *parser;
  struct dlep_parser_tlv *tlv;
  struct dlep_extension_signal *extsig;
  size_t s, t;

  parser = &session->parser;

  extsig = NULL;
  for (s = 0; s < ext->signal_count; s++) {
    if (ext->signals[s].id == signal_type) {
      extsig = &ext->signals[s];
      break;
    }
  }

  if (!extsig) {
    return DLEP_NEW_PARSER_OKAY;
  }

  for (t = 0; t < extsig->mandatory_tlv_count; t++) {
    tlv = dlep_parser_get_tlv(parser, extsig->mandatory_tlvs[t]);
    if (!tlv) {
      OONF_WARN(session->log_source,
        "Could not find tlv data for"
        " mandatory TLV %u in extension %d",
        extsig->mandatory_tlvs[t], ext->id);
      return DLEP_NEW_PARSER_INTERNAL_ERROR;
    }

    if (tlv->tlv_first == -1) {
      OONF_WARN(session->log_source,
        "Missing mandatory TLV"
        " %u in extension %d",
        extsig->mandatory_tlvs[t], ext->id);
      return DLEP_NEW_PARSER_MISSING_MANDATORY_TLV;
    }
  }
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Check if all duplicate TLVs were allowed to be duplicates
 * @param session dlep session
 * @param ext dlep extension
 * @param signal_type dlep signal/message type
 * @return dlep parser status
 */
static enum dlep_parser_error
_check_duplicate(struct dlep_session *session, struct dlep_extension *ext, int32_t signal_type) {
  struct dlep_session_parser *parser;
  struct dlep_parser_tlv *tlv;
  struct dlep_extension_signal *extsig;
  size_t s, t, dt;
  bool okay;

  parser = &session->parser;

  extsig = NULL;
  for (s = 0; s < ext->signal_count; s++) {
    extsig = &ext->signals[s];
    if (ext->signals[s].id == signal_type) {
      extsig = &ext->signals[s];
      break;
    }
  }

  if (!extsig) {
    return DLEP_NEW_PARSER_OKAY;
  }

  for (t = 0; t < extsig->supported_tlv_count; t++) {
    tlv = avl_find_element(&parser->allowed_tlvs, &extsig->supported_tlvs[t], tlv, _node);
    if (tlv == NULL || tlv->tlv_first == tlv->tlv_last) {
      continue;
    }

    okay = false;
    for (dt = 0; dt < extsig->duplicate_tlv_count; dt++) {
      if (extsig->duplicate_tlvs[dt] == tlv->id) {
        okay = true;
        break;
      }
    }
    if (!okay) {
      OONF_WARN(session->log_source,
        "Duplicate not allowed"
        " for TLV %u in extension %d",
        tlv->id, ext->id);
      return DLEP_NEW_PARSER_DUPLICATE_TLV;
    }
  }
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Call extension processing hooks for parsed signal/message
 * @param session dlep session
 * @param ext dlep_extension
 * @param signal_type dlep signal/message type
 * @return dlep parser status
 */
static enum dlep_parser_error
_call_extension_processing(struct dlep_session *session, struct dlep_extension *ext, int32_t signal_type) {
  size_t s;

  for (s = 0; s < ext->signal_count; s++) {
    if (ext->signals[s].id != signal_type) {
      continue;
    }

    if (session->radio) {
      if (ext->signals[s].process_radio && ext->signals[s].process_radio(ext, session)) {
        OONF_DEBUG(session->log_source, "Error in radio signal processing of extension '%s'", ext->name);
        return -1;
      }
    }
    else {
      if (ext->signals[s].process_router && ext->signals[s].process_router(ext, session)) {
        OONF_DEBUG(session->log_source, "Error in router signal processing of extension '%s'", ext->name);
        return -1;
      }
    }
    break;
  }
  return DLEP_NEW_PARSER_OKAY;
}

/**
 * Add a TLV to the allowed TLVs of a DLEP session
 * @param parser dlep session parser
 * @param id DLEP TLV id
 * @return dlep parser TLV, NULL if out of memory
 */
static struct dlep_parser_tlv *
_add_session_tlv(struct dlep_session_parser *parser, uint16_t id) {
  struct dlep_parser_tlv *tlv;

  tlv = oonf_class_malloc(&_tlv_class);
  if (!tlv) {
    return NULL;
  }

  tlv->id = id;
  tlv->_node.key = &tlv->id;
  tlv->tlv_first = -1;
  tlv->tlv_last = -1;

  avl_insert(&parser->allowed_tlvs, &tlv->_node);
  return tlv;
}
