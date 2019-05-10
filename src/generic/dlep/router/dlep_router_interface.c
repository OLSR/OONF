
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
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>

#include <oonf/generic/dlep/dlep_extension.h>
#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_interface.h>
#include <oonf/generic/dlep/dlep_session.h>
#include <oonf/generic/dlep/dlep_writer.h>

#include <oonf/generic/dlep/router/dlep_router.h>
#include <oonf/generic/dlep/router/dlep_router_interface.h>

#include <oonf/generic/dlep/ext_base_ip/ip.h>
#include <oonf/generic/dlep/ext_base_metric/metric.h>
#include <oonf/generic/dlep/ext_base_proto/proto_router.h>
#include <oonf/generic/dlep/ext_l1_statistics/l1_statistics.h>
#include <oonf/generic/dlep/ext_l2_statistics/l2_statistics.h>
#include <oonf/generic/dlep/ext_radio_attributes/radio_attributes.h>
#include <oonf/generic/dlep/ext_lid/lid.h>
#include <oonf/generic/dlep/ext_dns/dns.h>
#include <oonf/generic/dlep/router/dlep_router_internal.h>
#include <oonf/generic/dlep/router/dlep_router_session.h>

static void _connect_to_setup(struct dlep_router_if *router_if);
static void _check_connect_to(struct dlep_router_if *router_if);
static void _cleanup_interface(struct dlep_router_if *interface);
static int _connect_to_if_changed(struct os_interface_listener *);
static void _cb_check_connect_to_status(struct oonf_timer_instance *);

static struct oonf_class _router_if_class = {
  .name = "DLEP router interface",
  .size = sizeof(struct dlep_router_if),
};

static bool _shutting_down;

#if 0
static struct oonf_layer2_origin _l2_origin = {
  .name = "dlep_router",
  .proactive = true,
  .priority = OONF_LAYER2_ORIGIN_RELIABLE,
};

static struct oonf_layer2_origin _l2_default_origin = {
  .name = "dlep_router_defaults",
  .proactive = false,
  .priority = OONF_LAYER2_ORIGIN_UNRELIABLE,
};
#endif

static struct oonf_timer_class _connect_to_watchdog_class = {
  .name = "connect_to watchdog",
  .callback = _cb_check_connect_to_status,
  .periodic = true,
};

/**
 * Initialize dlep router interface framework. This will also
 * initialize the dlep router session framework.
 */
void
dlep_router_interface_init(void) {
  oonf_class_add(&_router_if_class);

  dlep_extension_init();
  dlep_session_init();
  dlep_router_session_init();
  dlep_base_proto_router_init();
  dlep_base_metric_init();
  dlep_base_ip_init();
  dlep_l1_statistics_init();
  dlep_l2_statistics_init();
  dlep_radio_attributes_init();
  dlep_lid_init();
  dlep_dns_init();

  _shutting_down = false;

#if 0
  oonf_layer2_origin_add(&_l2_origin);
  oonf_layer2_origin_add(&_l2_default_origin);
#endif

  oonf_timer_add(&_connect_to_watchdog_class);
}

/**
 * Cleanup dlep router interface framework. This will also cleanup
 * all dlep router sessions.
 */
void
dlep_router_interface_cleanup(void) {
  struct dlep_router_if *interf, *it;

  avl_for_each_element_safe(dlep_if_get_tree(false), interf, interf._node, it) {
    dlep_router_remove_interface(interf);
  }

  oonf_class_remove(&_router_if_class);

  dlep_base_ip_cleanup();
  dlep_router_session_cleanup();
  dlep_extension_cleanup();
#if 0
  oonf_layer2_origin_remove(&_l2_origin);
  oonf_layer2_origin_remove(&_l2_default_origin);
#endif
  oonf_timer_remove(&_connect_to_watchdog_class);
}

/**
 * Get a dlep router interface by layer2 interface name
 * @param l2_ifname interface name
 * @return dlep router interface, NULL if not found
 */
struct dlep_router_if *
dlep_router_get_by_layer2_if(const char *l2_ifname) {
  struct dlep_router_if *interf;

  return avl_find_element(dlep_if_get_tree(false), l2_ifname, interf, interf._node);
}

/**
 * Get a dlep router interface by dlep datapath name
 * @param ifname interface name
 * @return dlep router interface, NULL if not found
 */
struct dlep_router_if *
dlep_router_get_by_datapath_if(const char *ifname) {
  struct dlep_router_if *interf;

  avl_for_each_element(dlep_if_get_tree(false), interf, interf._node) {
    if (strcmp(interf->interf.udp_config.interface, ifname) == 0) {
      return interf;
    }
  }
  return NULL;
}

/**
 * Add a new dlep interface or get existing one with same name.
 * @param ifname interface name
 * @return dlep router interface, NULL if allocation failed
 */
struct dlep_router_if *
dlep_router_add_interface(const char *ifname) {
  struct dlep_router_if *interface;
  char buffer[64];

  interface = dlep_router_get_by_layer2_if(ifname);
  if (interface) {
    OONF_DEBUG(LOG_DLEP_ROUTER, "use existing instance for %s", ifname);
    return interface;
  }

  interface = oonf_class_malloc(&_router_if_class);
  if (!interface) {
    return NULL;
  }

  snprintf(buffer, sizeof(buffer), "dlep_rt_%s", ifname);
  interface->l2_origin.name = strdup(buffer);
  interface->l2_origin.priority = OONF_LAYER2_ORIGIN_RELIABLE,
  interface->l2_origin.proactive = true;
  oonf_layer2_origin_add(&interface->l2_origin);

  snprintf(buffer, sizeof(buffer), "dlep_rtd_%s", ifname);
  interface->l2_default_origin.name = strdup(buffer);
  interface->l2_default_origin.priority = OONF_LAYER2_ORIGIN_UNRELIABLE,
  interface->l2_default_origin.proactive = false;
  oonf_layer2_origin_add(&interface->l2_origin);

  if (dlep_if_add(&interface->interf, ifname, &interface->l2_origin,
      &interface->l2_default_origin, _connect_to_if_changed, LOG_DLEP_ROUTER, false)) {
    oonf_class_free(&_router_if_class, interface);
    return NULL;
  }

  /* prepare timer */
  interface->_connect_to_watchdog.class = &_connect_to_watchdog_class;

  OONF_DEBUG(LOG_DLEP_ROUTER, "Add session %s", ifname);
  return interface;
}

/**
 * Remove dlep router interface
 * @param interface dlep router interface
 */
void
dlep_router_remove_interface(struct dlep_router_if *interface) {
  /* close all sessions */
  _cleanup_interface(interface);

  /* cleanup generic interface */
  dlep_if_remove(&interface->interf);

  /* remove session */
  free(interface->interf.session.cfg.peer_type);
  oonf_class_free(&_router_if_class, interface);
}

/**
 * Apply new settings to dlep router interface. This will close all
 * existing dlep sessions.
 * @param interf dlep router interface
 */
void
dlep_router_apply_interface_settings(struct dlep_router_if *interf) {
  struct dlep_extension *ext;

  oonf_packet_apply_managed(&interf->interf.udp, &interf->interf.udp_config);

  _cleanup_interface(interf);

  if (!netaddr_is_unspec(&interf->connect_to_addr)) {
    _connect_to_setup(interf);
  }
  else {
    oonf_timer_stop(&interf->_connect_to_watchdog);
  }

  avl_for_each_element(dlep_extension_get_tree(), ext, _node) {
    if (ext->cb_session_apply_router) {
      ext->cb_session_apply_router(&interf->interf.session);
    }
  }
}

/**
 * Send all active sessions a Peer Terminate signal
 */
void
dlep_router_terminate_all_sessions(void) {
  struct dlep_router_if *interf;
  struct dlep_router_session *router_session;

  _shutting_down = true;

  avl_for_each_element(dlep_if_get_tree(false), interf, interf._node) {
    avl_for_each_element(&interf->interf.session_tree, router_session, _node) {
      dlep_session_terminate(&router_session->session, DLEP_STATUS_OKAY, "DLEP router is shutting down");
    }
  }
}

/**
* open a direct TCP connection for this interface
* @param router_if router interface
*/
static void
_connect_to_setup(struct dlep_router_if *router_if) {
  struct os_interface *os_if;
  const struct os_interface_ip *result;
  union netaddr_socket local;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  os_if = router_if->interf.session.l2_listener.data;

  OONF_DEBUG(LOG_DLEP_ROUTER, "Connect directly to [%s]:%d", netaddr_to_string(&nbuf, &router_if->connect_to_addr),
      router_if->connect_to_port);

  /* start watchdog */
  oonf_timer_set(&router_if->_connect_to_watchdog, 1000);

  result = os_interface_get_prefix_from_dst(&router_if->connect_to_addr, os_if);
  if (result) {
    /* initialize local and remote socket */
    netaddr_socket_init(&local, &result->address, 0, os_if->index);
    netaddr_socket_init(&router_if->connect_to, &router_if->connect_to_addr, router_if->connect_to_port, os_if->index);

    dlep_router_add_session(router_if, &local, &router_if->connect_to);
  }
}

/**
 * Close all existing dlep sessions of a dlep interface
 * @param interface dlep router interface
 */
static void
_cleanup_interface(struct dlep_router_if *interface) {
  struct dlep_router_session *stream, *it;

  /* close TCP connection and socket */
  avl_for_each_element_safe(&interface->interf.session_tree, stream, _node, it) {
    dlep_router_remove_session(stream);
  }
}

/**
 * check if connect_to session is up and running. If not, restart it.
 * @param router_if router interface
 */
static void
_check_connect_to(struct dlep_router_if *router_if) {
  struct dlep_router_session *connect_to_session;

  if (netaddr_is_unspec(&router_if->connect_to_addr)) {
    /* do not connect */
    return;
  }

  connect_to_session = dlep_router_get_session(router_if, &router_if->connect_to);
  if (connect_to_session != NULL
    && (connect_to_session->session._peer_state == DLEP_PEER_NOT_CONNECTED
    || connect_to_session->session._peer_state == DLEP_PEER_TERMINATED)) {
    /* cleanup not working session */
    dlep_router_remove_session(connect_to_session);
    connect_to_session = NULL;
  }

  if (!connect_to_session) {
    _connect_to_setup(router_if);
  }
  return;
}

/**
* Interface listener to (re-)establish connect_to session if it failed.
* @param interf interface listener that triggered
* @return always 0
*/
static int
_connect_to_if_changed(struct os_interface_listener *interf) {
  struct dlep_router_if *router_if;

  router_if = container_of(interf, struct dlep_router_if, interf.session.l2_listener);
  _check_connect_to(router_if);
  return 0;
}

/**
 * Timer callback to watch connect_to session status
 * @param instance watchdog timer instance
 */
static void
_cb_check_connect_to_status(struct oonf_timer_instance *instance) {
  struct dlep_router_if *router_if;

  router_if = container_of(instance, struct dlep_router_if, _connect_to_watchdog);
  _check_connect_to(router_if);
}
