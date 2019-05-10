
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

#ifndef DLEP_RADIO_INTERFACE_H_
#define DLEP_RADIO_INTERFACE_H_

#include <oonf/libcommon/avl.h>
#include <oonf/oonf.h>
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_stream_socket.h>

#include <oonf/generic/dlep/dlep_interface.h>
#include <oonf/generic/dlep/dlep_session.h>

/**
 * DLEP radio session
 */
struct dlep_radio_if {
  /*! generic DLEP interface session */
  struct dlep_if interf;

  /*! TCP socket for client session */
  struct oonf_stream_managed tcp;

  /*! configuration of TCP socket */
  struct oonf_stream_managed_config tcp_config;

  /* layer2 origin for this interface */
  struct oonf_layer2_origin l2_origin;

  /* layer2 origin for this interface default values*/
  struct oonf_layer2_origin l2_default_origin;
};

int dlep_radio_interface_init(void);
void dlep_radio_interface_cleanup(void);

struct dlep_radio_if *dlep_radio_get_by_layer2_if(const char *ifname);
struct dlep_radio_if *dlep_radio_add_interface(const char *l2_ifname);
void dlep_radio_remove_interface(struct dlep_radio_if *);

struct dlep_radio_if *dlep_radio_get_by_datapath_if(const char *ifname);

void dlep_radio_apply_interface_settings(struct dlep_radio_if *interface);

void dlep_radio_terminate_all_sessions(void);

#endif /* DLEP_RADIO_INTERFACE_H_ */
