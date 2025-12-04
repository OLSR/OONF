
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

#ifndef DLEP_INTERFACE_H_
#define DLEP_INTERFACE_H_

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/generic/dlep/dlep_session.h>

#define DLEP_IF_UDP_NONE_STR           "none"
#define DLEP_IF_UDP_SINGLE_SESSION_STR "single_session"
#define DLEP_IF_UDP_ALWAYS_STR         "always"

enum dlep_if_udp_mode{
  /* never handle UDP */
  DLEP_IF_UDP_NONE,

  /* just use UDP if no session is active */
  DLEP_IF_UDP_SINGLE_SESSION,

  /* always handle UDP */
  DLEP_IF_UDP_ALWAYS,
};

/**
 * Interface that is used for one or multiple dlep sessions
 */
struct dlep_if {
  /*! pseudo session for UDP communication on interface */
  struct dlep_session session;

  /*! name of layer2 interface */
  char l2_ifname[IF_NAMESIZE];

  /*! UDP socket for discovery */
  struct oonf_packet_managed udp;

  /*! UDP socket configuration */
  struct oonf_packet_managed_config udp_config;

  /*! dynamic buffer for UDP output */
  struct autobuf udp_out;

  /*! decides when/if UDP should be sent/processed */
  enum dlep_if_udp_mode udp_mode;

  /*! true if this interface is used for DLEP radio */
  bool radio;

  /*! hook into interface tree, interface name is the key */
  struct avl_node _node;

  /*! tree of all sessions of same type (radio/router) on this interface */
  struct avl_tree session_tree;
};

struct avl_tree *dlep_if_get_tree(bool radio);
int dlep_if_add(struct dlep_if *interf, const char *ifname, const struct oonf_layer2_origin *l2_origin,
  const struct oonf_layer2_origin *l2_default_origin,
  int (*if_changed)(struct os_interface_listener *), enum oonf_log_source log_src, bool radio);
void dlep_if_remove(struct dlep_if *interface);

#endif /* DLEP_INTERFACE_H_ */
