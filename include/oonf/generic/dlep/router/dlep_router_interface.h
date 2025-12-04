
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

#ifndef DLEP_ROUTER_INTERFACE_H_
#define DLEP_ROUTER_INTERFACE_H_

#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_interface.h>
#include <oonf/generic/dlep/dlep_session.h>

/**
 * DLEP router interface
 */
struct dlep_router_if {
  /*! generic DLEP interface */
  struct dlep_if interf;

  /* combined address/port we are directly connected to */
  union netaddr_socket connect_to;

  /*! IP address to directly connect router to */
  struct netaddr connect_to_addr;

  /*! TCP port to directly connect router to */
  int32_t connect_to_port;

  /* layer2 origin for this interface */
  struct oonf_layer2_origin l2_origin;

  /* layer2 origin for this interface default values*/
  struct oonf_layer2_origin l2_default_origin;

  /* timer to make sure we stay connected */
  struct oonf_timer_instance _connect_to_watchdog;
};

void dlep_router_interface_init(void);
void dlep_router_interface_cleanup(void);

struct dlep_router_if *dlep_router_get_by_layer2_if(const char *ifname);
struct dlep_router_if *dlep_router_get_by_datapath_if(const char *ifname);
struct dlep_router_if *dlep_router_add_interface(const char *ifname);
void dlep_router_remove_interface(struct dlep_router_if *);

void dlep_router_apply_interface_settings(struct dlep_router_if *);
void dlep_router_terminate_all_sessions(void);

#endif /* DLEP_ROUTER_INTERFACE_H_ */
