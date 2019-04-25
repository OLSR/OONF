
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
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_session.h>
#include <oonf/generic/dlep/dlep_writer.h>
#include <oonf/generic/dlep/radio/dlep_radio.h>
#include <oonf/generic/dlep/radio/dlep_radio_interface.h>
#include <oonf/generic/dlep/radio/dlep_radio_internal.h>
#include <oonf/generic/dlep/radio/dlep_radio_session.h>

static int _cb_incoming_tcp(struct oonf_stream_session *);
static void _cb_tcp_lost(struct oonf_stream_session *);
static enum oonf_stream_session_state _cb_tcp_receive_data(struct oonf_stream_session *);
static void _cb_send_buffer(struct dlep_session *session, int af_family);
static void _cb_end_session(struct dlep_session *session);

static struct oonf_class _radio_session_class = {
  .name = "DLEP TCP session",
  .size = sizeof(struct dlep_radio_session),
};

/**
 * Initialize framework for dlep radio sessions
 */
void
dlep_radio_session_init(void) {
  oonf_class_add(&_radio_session_class);
}

/**
 * Cleanup dlep radio session framework
 */
void
dlep_radio_session_cleanup(void) {
  oonf_class_remove(&_radio_session_class);
}

/**
 * Initialize the callbacks for a dlep tcp socket
 * @param config tcp socket config
 */
void
dlep_radio_session_initialize_tcp_callbacks(struct oonf_stream_config *config) {
  config->memcookie = &_radio_session_class;
  config->init_session = _cb_incoming_tcp;
  config->cleanup_session = _cb_tcp_lost;
  config->receive_data = _cb_tcp_receive_data;
}

/**
 * Remove existing dlep radio session
 * @param radio_session dlep radio session
 */
void
dlep_radio_remove_session(struct dlep_radio_session *radio_session) {
  oonf_stream_close(&radio_session->stream);
}

/**
 * Callback triggered when a new tcp session is accepted by the local socket
 * @param tcp_session pointer to tcp session object
 * @return always 0
 */
static int
_cb_incoming_tcp(struct oonf_stream_session *tcp_session) {
  struct dlep_radio_session *radio_session;
  struct dlep_radio_if *interface;
  struct dlep_extension *ext;

  radio_session = container_of(tcp_session, struct dlep_radio_session, stream);
  interface = container_of(tcp_session->stream_socket->managed, struct dlep_radio_if, tcp);

  /* initialize back pointer */
  radio_session->interface = interface;

  /* activate session */
  if (dlep_session_add(&radio_session->session, interface->interf.l2_ifname, interface->interf.session.l2_origin,
        interface->interf.session.l2_default_origin, &tcp_session->out, true, NULL, LOG_DLEP_RADIO)) {
    return -1;
  }
  radio_session->session.restrict_signal = DLEP_SESSION_INITIALIZATION;
  radio_session->session.cb_send_buffer = _cb_send_buffer;
  radio_session->session.cb_end_session = _cb_end_session;
  memcpy(&radio_session->session.cfg, &interface->interf.session.cfg, sizeof(radio_session->session.cfg));
  memcpy(
    &radio_session->session.remote_socket, &tcp_session->remote_socket, sizeof(radio_session->session.remote_socket));

  /* attach to session tree of interface */
  radio_session->_node.key = &radio_session->stream.remote_socket;
  avl_insert(&interface->interf.session_tree, &radio_session->_node);

  /* copy socket information */
  memcpy(
    &radio_session->session.remote_socket, &tcp_session->remote_socket, sizeof(radio_session->session.remote_socket));

  /* inform all extensions */
  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if (ext->cb_session_init_radio) {
      ext->cb_session_init_radio(&radio_session->session);
    }
  }

  return 0;
}

/**
 * Callback when a tcp session is lost and must be closed
 * @param tcp_session pointer to tcp session object
 */
static void
_cb_tcp_lost(struct oonf_stream_session *tcp_session) {
  struct dlep_radio_session *radio_session;
  struct dlep_extension *ext;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  radio_session = container_of(tcp_session, struct dlep_radio_session, stream);

  OONF_DEBUG(LOG_DLEP_RADIO, "Lost tcp session to %s", netaddr_socket_to_string(&nbuf, &tcp_session->remote_socket));

  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if (ext->cb_session_cleanup_radio) {
      ext->cb_session_cleanup_radio(&radio_session->session);
    }
  }

  /* kill embedded session object */
  dlep_session_remove(&radio_session->session);

  /* remove from session tree of interface */
  avl_remove(&radio_session->interface->interf.session_tree, &radio_session->_node);
}

/**
 * Callback to receive data over oonf_stream_socket
 * @param tcp_session pointer to tcp session
 * @return tcp session state
 */
static enum oonf_stream_session_state
_cb_tcp_receive_data(struct oonf_stream_session *tcp_session) {
  struct dlep_radio_session *radio_session;

  radio_session = container_of(tcp_session, struct dlep_radio_session, stream);

  return dlep_session_process_tcp(tcp_session, &radio_session->session);
}

static void
_cb_send_buffer(struct dlep_session *session, int af_family __attribute((unused))) {
  struct dlep_radio_session *radio_session;

  if (!abuf_getlen(session->writer.out)) {
    return;
  }

  OONF_DEBUG(session->log_source, "Send buffer %" PRINTF_SIZE_T_SPECIFIER " bytes", abuf_getlen(session->writer.out));

  /* get pointer to radio interface */
  radio_session = container_of(session, struct dlep_radio_session, session);

  oonf_stream_flush(&radio_session->stream);
}

static void
_cb_end_session(struct dlep_session *session) {
  struct dlep_radio_session *radio_session;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  /* get pointer to radio interface */
  radio_session = container_of(session, struct dlep_radio_session, session);

  OONF_DEBUG(session->log_source, "Ending session to %s",
             netaddr_socket_to_string(&nbuf, &radio_session->stream.remote_socket));
  dlep_radio_remove_session(radio_session);
}
