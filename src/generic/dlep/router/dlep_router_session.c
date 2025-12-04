
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

#include <errno.h>
#include <unistd.h>

#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>

#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_session.h>
#include <oonf/generic/dlep/dlep_writer.h>
#include <oonf/generic/dlep/router/dlep_router_interface.h>
#include <oonf/generic/dlep/router/dlep_router_session.h>
#include <oonf/generic/dlep/dlep_internal.h>
#include <oonf/generic/dlep/dlep.h>

static void _cb_socket_terminated(struct oonf_stream_socket *stream_socket);
static void _cb_tcp_lost(struct oonf_stream_session *);
static enum oonf_stream_session_state _cb_tcp_receive_data(struct oonf_stream_session *);
static void _cb_send_buffer(struct dlep_session *session, int af_family);
static void _cb_end_session(struct dlep_session *session);

/* session objects */
static struct oonf_class _router_session_class = {
  .name = OONF_CLASS_DLEP_ROUTER_SESSION,
  .size = sizeof(struct dlep_router_session),
};

/**
 * Initialize dlep router session framework
 */
void
dlep_router_session_init(void) {
  oonf_class_add(&_router_session_class);
}

/**
 * Cleanup dlep router session framework
 */
void
dlep_router_session_cleanup(void) {
  oonf_class_remove(&_router_session_class);
}

/**
 * Get dlep router session based on interface and remote socket
 * @param interf dlep router interface
 * @param remote remote IP socket
 * @return dlep router session, NULL if not found
 */
struct dlep_router_session *
dlep_router_get_if_session(struct dlep_router_if *interf, union netaddr_socket *remote) {
  struct dlep_router_session *session;

  return avl_find_element(&interf->interf.session_tree, remote, session, session._node);
}

/**
 * Add new dlep router session or return existing one
 * @param interf dlep router interface
 * @param local local IP socket
 * @param remote remote IP socket
 * @return dlep router session, NULL if not found
 */
struct dlep_router_session *
dlep_router_add_session(struct dlep_router_if *interf, union netaddr_socket *local, union netaddr_socket *remote) {
  struct dlep_router_session *router_session;
  struct dlep_extension *ext;
  struct netaddr_str nbuf1, nbuf2;

  router_session = dlep_router_get_if_session(interf, remote);
  if (router_session) {
    OONF_DEBUG(LOG_DLEP_ROUTER,
      "use existing instance on"
      " %s for %s",
      interf->interf.l2_ifname, netaddr_socket_to_string(&nbuf1, remote));
    return router_session;
  }

  /* initialize tcp session instance */
  router_session = oonf_class_malloc(&_router_session_class);
  if (!router_session) {
    return NULL;
  }

  /* initialize tree node */
  memcpy(&router_session->session.remote_socket, remote, sizeof(*remote));
  router_session->session._node.key = &router_session->session.remote_socket;

  /* configure and open TCP session */
  router_session->tcp.config.session_timeout = 120000; /* 120 seconds */
  router_session->tcp.config.maximum_input_buffer = 4096;
  router_session->tcp.config.allowed_sessions = 3;
  router_session->tcp.config.cleanup_session = _cb_tcp_lost;
  router_session->tcp.config.cleanup_socket = _cb_socket_terminated;
  router_session->tcp.config.receive_data = _cb_tcp_receive_data;

  OONF_DEBUG(LOG_DLEP_ROUTER, "Connect DLEP session from %s to %s", netaddr_socket_to_string(&nbuf1, local),
    netaddr_socket_to_string(&nbuf2, remote));

  if (oonf_stream_add(&router_session->tcp, local)) {
    OONF_WARN(
      LOG_DLEP_ROUTER, "Could not open TCP client for local address %s", netaddr_socket_to_string(&nbuf1, local));
    dlep_router_remove_session(router_session);
    return NULL;
  }

  /* open stream */
  router_session->stream = oonf_stream_connect_to(&router_session->tcp, remote);
  if (!router_session->stream) {
    OONF_WARN(LOG_DLEP_ROUTER, "Could not open TCP client on from %s to %s", netaddr_socket_to_string(&nbuf1, local),
      netaddr_socket_to_string(&nbuf2, remote));
    dlep_router_remove_session(router_session);
    return NULL;
  }

  if (dlep_session_add(&router_session->session, interf->interf.l2_ifname, interf->interf.session.l2_origin,
        interf->interf.session.l2_default_origin, &router_session->stream->out, false, NULL, LOG_DLEP_ROUTER)) {
    dlep_router_remove_session(router_session);
    return NULL;
  }
  router_session->session.restrict_signal = DLEP_SESSION_INITIALIZATION_ACK;
  router_session->session.cb_send_buffer = _cb_send_buffer;
  router_session->session.cb_end_session = _cb_end_session;
  memcpy(&router_session->session.cfg, &interf->interf.session.cfg, sizeof(router_session->session.cfg));

  /* initialize back pointer */
  router_session->interface = interf;

  /* copy local socket */
  memcpy(&router_session->session.local_socket, &router_session->stream->stream_socket->local_socket,
         sizeof(router_session->session.local_socket));

  /* add session to interface */
  avl_insert(&interf->interf.session_tree, &router_session->session._node);

  /* inform all extensions */
  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if (ext->cb_session_init_router) {
      ext->cb_session_init_router(&router_session->session);
    }
  }

  return router_session;
}

/**
 * Remove existing dlep router session
 * @param router_session dlep router session
 */
void
dlep_router_remove_session(struct dlep_router_session *router_session) {
  if (router_session->stream) {
    oonf_stream_close(router_session->stream);
    router_session->stream = NULL;
  }
  oonf_stream_remove(&router_session->tcp, false);
}

/**
 * Callback triggered when tcp socket (not session) has been terminated
 * @param stream_socket terminated socket
 */
static void
_cb_socket_terminated(struct oonf_stream_socket *stream_socket) {
  struct dlep_router_session *router_session;

  router_session = container_of(stream_socket, struct dlep_router_session, tcp);

  oonf_class_free(&_router_session_class, router_session);
}
/**
 * Callback triggered when tcp session was lost and will be removed
 * @param tcp_session tcp session
 */
static void
_cb_tcp_lost(struct oonf_stream_session *tcp_session) {
  struct dlep_extension *ext;
  struct dlep_router_session *router_session;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  router_session = container_of(tcp_session->stream_socket, struct dlep_router_session, tcp);

  OONF_DEBUG(LOG_DLEP_ROUTER, "Lost tcp session to %s", netaddr_socket_to_string(&nbuf, &tcp_session->remote_socket));

  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if (ext->cb_session_cleanup_router) {
      ext->cb_session_cleanup_router(&router_session->session);
    }
  }

  /* kill embedded session object */
  dlep_session_remove(&router_session->session);

  /* remove from session tree of interface */
  if (avl_is_node_added(&router_session->session._node)) {
    avl_remove(&router_session->interface->interf.session_tree, &router_session->session._node);
  }
}

/**
 * Receive tcp data via oonf_stream_socket
 * @param tcp_session tcp session to DLEP partner
 * @return new state of TCP session
 */
static enum oonf_stream_session_state
_cb_tcp_receive_data(struct oonf_stream_session *tcp_session) {
  struct dlep_router_session *router_session;

  router_session = container_of(tcp_session->stream_socket, struct dlep_router_session, tcp);

  return dlep_session_process_tcp(tcp_session, &router_session->session);
}

/**
 * Callback triggered to send current buffer to the network
 * @param session dlep session
 * @param af_family address family
 */
static void
_cb_send_buffer(struct dlep_session *session, int af_family __attribute((unused))) {
  struct dlep_router_session *router_session;

  if (!abuf_getlen(session->writer.out)) {
    return;
  }

  OONF_DEBUG(session->log_source, "Send buffer %" PRINTF_SIZE_T_SPECIFIER " bytes", abuf_getlen(session->writer.out));

  /* get pointer to radio interface */
  router_session = container_of(session, struct dlep_router_session, session);

  oonf_stream_flush(router_session->stream);
}

/**
 * Callback triggered when session is terminated
 * @param session dlep session
 */
static void
_cb_end_session(struct dlep_session *session) {
  struct dlep_router_session *router_session;

  /* get pointer to radio interface */
  router_session = container_of(session, struct dlep_router_session, session);

  dlep_router_remove_session(router_session);
}
