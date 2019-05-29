
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

#ifndef DLEP_ROUTER_SESSION_H_
#define DLEP_ROUTER_SESSION_H_

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>

#include <oonf/generic/dlep/router/dlep_router_interface.h>

/**
 * session state of a router
 */
enum dlep_router_session_state
{
  /*! session is still initializing */
  DLEP_ROUTER_SESSION_INIT,

  /*! session is active */
  DLEP_ROUTER_SESSION_ACTIVE,

  /*! session is being terminated */
  DLEP_ROUTER_SESSION_TERMINATE,
};

/**
 * DLEP session of a router
 */
struct dlep_router_session {
  /*! basic struct for tcp stream */
  struct oonf_stream_session *stream;

  /*! TCP client socket for session */
  struct oonf_stream_socket tcp;

  /*! generic DLEP session */
  struct dlep_session session;

  /*! back pointer to interface session */
  struct dlep_router_if *interface;
};

void dlep_router_session_init(void);
void dlep_router_session_cleanup(void);

struct dlep_router_session *dlep_router_get_if_session(struct dlep_router_if *interf, union netaddr_socket *remote);
struct dlep_router_session *dlep_router_add_session(struct dlep_router_if *interf,
    union netaddr_socket *local, union netaddr_socket *remote);
void dlep_router_remove_session(struct dlep_router_session *);

static INLINE struct dlep_router_session *
dlep_router_get_session(struct dlep_session *session) {
  if (session->radio) {
    return NULL;
  }
  return container_of(session, struct dlep_router_session, session);
}

#endif /* DLEP_ROUTER_SESSION_H_ */
