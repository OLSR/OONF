
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
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_session.h>
#include <oonf/generic/dlep/dlep_writer.h>

#include <oonf/generic/dlep/radio/dlep_radio.h>
#include <oonf/generic/dlep/radio/dlep_radio_interface.h>

#include <oonf/generic/dlep/ext_base_ip/ip.h>
#include <oonf/generic/dlep/ext_base_metric/metric.h>
#include <oonf/generic/dlep/ext_base_proto/proto_radio.h>
#include <oonf/generic/dlep/ext_l1_statistics/l1_statistics.h>
#include <oonf/generic/dlep/ext_l2_statistics/l2_statistics.h>
#include <oonf/generic/dlep/ext_radio_attributes/radio_attributes.h>
#include <oonf/generic/dlep/ext_lid/lid.h>
#include <oonf/generic/dlep/ext_dns/dns.h>
#include <oonf/generic/dlep/radio/dlep_radio_internal.h>
#include <oonf/generic/dlep/radio/dlep_radio_session.h>

static void _cleanup_interface(struct dlep_radio_if *interface);

/* DLEP interfaces */
static struct oonf_class _interface_class = {
  .name = "DLEP radio interface",
  .size = sizeof(struct dlep_radio_if),
};

static bool _shutting_down;

#if 0
static struct oonf_layer2_origin _l2_origin = {
  .name = "dlep_radio",
  .proactive = true,
  .priority = OONF_LAYER2_ORIGIN_RELIABLE,
};

static struct oonf_layer2_origin _l2_default_origin = {
  .name = "dlep_radio_defaults",
  .proactive = false,
  .priority = OONF_LAYER2_ORIGIN_DEFAULT,
};
#endif

/**
 * Initialize everything for dlep radio interfaces. This function also
 * initializes the dlep sessions.
 * @return -1 if an error happened, 0 otherwise
 */
int
dlep_radio_interface_init(void) {
  oonf_class_add(&_interface_class);

  dlep_extension_init();
  dlep_session_init();
  dlep_radio_session_init();
  dlep_base_proto_radio_init();
  dlep_base_ip_init();
  dlep_base_metric_init();
  dlep_l1_statistics_init();
  dlep_l2_statistics_init();
  dlep_radio_attributes_init();
  dlep_lid_init();
  dlep_dns_init();
#if 0
  oonf_layer2_origin_add(&_l2_origin);
  oonf_layer2_origin_add(&_l2_default_origin);
#endif
  _shutting_down = false;
  return 0;
}

/**
 * Cleanup everything allocated for dlep radio interfaces. This will
 * also clean up all dlep sessions.
 */
void
dlep_radio_interface_cleanup(void) {
  struct dlep_radio_if *interf, *it;

  avl_for_each_element_safe(dlep_if_get_tree(true), interf, interf._node, it) {
    dlep_radio_remove_interface(interf);
  }

  oonf_class_remove(&_interface_class);
  dlep_radio_session_cleanup();
  dlep_extension_cleanup();
#if 0
  oonf_layer2_origin_remove(&_l2_origin);
  oonf_layer2_origin_remove(&_l2_default_origin);
#endif
}

/**
 * Get a dlep radio interface by layer2 interface name
 * @param l2_ifname interface name
 * @return dlep radio interface, NULL if not found
 */
struct dlep_radio_if *
dlep_radio_get_by_layer2_if(const char *l2_ifname) {
  struct dlep_radio_if *interf;

  return avl_find_element(dlep_if_get_tree(true), l2_ifname, interf, interf._node);
}

/**
 * Get a dlep radio interface by dlep datapath name
 * @param ifname interface name
 * @return dlep radio interface, NULL if not found
 */
struct dlep_radio_if *
dlep_radio_get_by_datapath_if(const char *ifname) {
  struct dlep_radio_if *interf;

  avl_for_each_element(dlep_if_get_tree(true), interf, interf._node) {
    if (strcmp(interf->interf.udp_config.interface, ifname) == 0) {
      return interf;
    }
  }
  return NULL;
}

/**
 * Add a new dlep radio interface to the database
 * (keep existing one if already there).
 * @param ifname interface name
 * @return dlep radio interface, NULL if allocation failed
 */
struct dlep_radio_if *
dlep_radio_add_interface(const char *ifname) {
  struct dlep_radio_if *interface;
  char buffer[64];

  interface = dlep_radio_get_by_layer2_if(ifname);
  if (interface) {
    return interface;
  }

  interface = oonf_class_malloc(&_interface_class);
  if (!interface) {
    return NULL;
  }

  snprintf(buffer, sizeof(buffer), "dlep_ra_%s", ifname);
  interface->l2_origin.name = strdup(buffer);
  interface->l2_origin.priority = OONF_LAYER2_ORIGIN_RELIABLE,
  interface->l2_origin.proactive = true;
  oonf_layer2_origin_add(&interface->l2_origin);

  snprintf(buffer, sizeof(buffer), "dlep_rad_%s", ifname);
  interface->l2_default_origin.name = strdup(buffer);
  interface->l2_default_origin.priority = OONF_LAYER2_ORIGIN_UNRELIABLE,
  interface->l2_default_origin.proactive = false;
  oonf_layer2_origin_add(&interface->l2_origin);


  if (dlep_if_add(&interface->interf, ifname, &interface->l2_origin,
      &interface->l2_default_origin, NULL, LOG_DLEP_RADIO, true)) {
    oonf_class_free(&_interface_class, interface);
    return NULL;
  }

  /* configure TCP server socket */
  interface->tcp.config.session_timeout = 120000; /* 120 seconds */
  interface->tcp.config.maximum_input_buffer = 4096;
  interface->tcp.config.allowed_sessions = 3;
  dlep_radio_session_initialize_tcp_callbacks(&interface->tcp.config);

  oonf_stream_add_managed(&interface->tcp);

  return interface;
}

/**
 * Remove a dlep radio interface
 * @param interface dlep radio interface
 */
void
dlep_radio_remove_interface(struct dlep_radio_if *interface) {
  /* close all sessions */
  _cleanup_interface(interface);

  /* cleanup tcp socket */
  oonf_stream_remove_managed(&interface->tcp, true);

  /* cleanup generic interface */
  dlep_if_remove(&interface->interf);

  /* free memory */
  oonf_stream_free_managed_config(&interface->tcp_config);
  free(interface->interf.session.cfg.peer_type);
  abuf_free(&interface->interf.udp_out);
  oonf_class_free(&_interface_class, interface);
}

/**
 * Apply settings for dlep radio interface
 * @param interface dlep radio interface
 */
void
dlep_radio_apply_interface_settings(struct dlep_radio_if *interface) {
  struct dlep_extension *ext;

  oonf_packet_apply_managed(&interface->interf.udp, &interface->interf.udp_config);
  oonf_stream_apply_managed(&interface->tcp, &interface->tcp_config);

  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if (ext->cb_session_apply_radio) {
      ext->cb_session_apply_radio(&interface->interf.session);
    }
  }
}

/**
 * Send all active sessions a Peer Terminate signal
 */
void
dlep_radio_terminate_all_sessions(void) {
  struct dlep_radio_if *interf;
  struct dlep_radio_session *radio_session;

  _shutting_down = true;

  avl_for_each_element(dlep_if_get_tree(true), interf, interf._node) {
    avl_for_each_element(&interf->interf.session_tree, radio_session, _node) {
      dlep_session_terminate(&radio_session->session, DLEP_STATUS_OKAY, "DLEP radio is shutting down");
    }
  }
}

/**
 * Close all existing dlep sessions of a dlep interface
 * @param interface dlep router interface
 */
static void
_cleanup_interface(struct dlep_radio_if *interface) {
  struct dlep_radio_session *stream, *it;

  /* close TCP connection and socket */
  avl_for_each_element_safe(&interface->interf.session_tree, stream, _node, it) {
    dlep_radio_remove_session(stream);
  }
}
