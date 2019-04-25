
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

#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_packet_socket.h>
#include <oonf/base/oonf_stream_socket.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/dlep/dlep_iana.h>
#include <oonf/generic/dlep/dlep_writer.h>
#include <oonf/generic/dlep/radio/dlep_radio.h>
#include <oonf/generic/dlep/radio/dlep_radio_interface.h>
#include <oonf/generic/dlep/radio/dlep_radio_internal.h>

/* prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _cleanup(void);
static void _initiate_shutdown(void);

static void _cb_config_changed(void);

/* configuration */
static const char *_UDP_MODE[] = {
  [DLEP_IF_UDP_NONE] = DLEP_IF_UDP_NONE_STR,
  [DLEP_IF_UDP_SINGLE_SESSION] = DLEP_IF_UDP_SINGLE_SESSION_STR,
  [DLEP_IF_UDP_ALWAYS] = DLEP_IF_UDP_ALWAYS_STR,
};

static struct cfg_schema_entry _radio_entries[] = {
  CFG_MAP_STRING_ARRAY(dlep_radio_if, interf.udp_config.interface, "datapath_if", "",
    "Name of interface to talk to dlep router (default is section name)", IF_NAMESIZE),

  CFG_MAP_STRING(dlep_radio_if, interf.session.cfg.peer_type, "peer_type", "OONF DLEP Radio",
    "Identification string of DLEP radio endpoint"),

  CFG_MAP_NETADDR_V4(dlep_radio_if, interf.udp_config.multicast_v4, "discovery_mc_v4",
    DLEP_WELL_KNOWN_MULTICAST_ADDRESS, "IPv4 address to send discovery UDP packet to", false, false),
  CFG_MAP_NETADDR_V6(dlep_radio_if, interf.udp_config.multicast_v6, "discovery_mc_v6",
    DLEP_WELL_KNOWN_MULTICAST_ADDRESS_6, "IPv6 address to send discovery UDP packet to", false, false),
  CFG_MAP_INT32_MINMAX(dlep_radio_if, interf.udp_config.port, "discovery_port", DLEP_WELL_KNOWN_MULTICAST_PORT_TXT,
    "UDP port for discovery packets", 0, 1, 65535),
  CFG_MAP_ACL_V46(dlep_radio_if, interf.udp_config.bindto, "discovery_bindto", "fe80::/64",
    "Filter to determine the binding of the UDP discovery socket"),

  CFG_MAP_INT32_MINMAX(dlep_radio_if, tcp_config.port, "session_port", DLEP_WELL_KNOWN_SESSION_PORT_TXT,
    "Server port for DLEP tcp sessions", 0, 1, 65535),
  CFG_MAP_ACL_V46(dlep_radio_if, tcp_config.bindto, "session_bindto", "169.254.0.0/16\0fe80::/10",
    "Filter to determine the binding of the TCP server socket"),
  CFG_MAP_ACL_V46(dlep_radio_if, tcp_config.acl, "session_acl", ACL_DEFAULT_ACCEPT,
    "Filter which IPs are allowed to connect to the TCP server socket"),
  CFG_MAP_CLOCK_MINMAX(dlep_radio_if, interf.session.cfg.heartbeat_interval, "heartbeat_interval", "1.000",
    "Interval in seconds between two heartbeat signals", 1000, 65535 * 1000),

  CFG_MAP_CHOICE(dlep_radio_if, interf.udp_mode, "udp_mode", DLEP_IF_UDP_SINGLE_SESSION_STR,
    "Determines the UDP behavior of the radio. 'none' never sends/processes UDP, 'single_session' only does"
    " if no DLEP session is active and 'always' always sends/processes UDP and allows multiple sessions",
    _UDP_MODE),

  CFG_MAP_BOOL(dlep_radio_if, interf.session.cfg.send_proxied, "proxied", "true",
    "Report 802.11s proxied mac address for neighbors"),
  CFG_MAP_BOOL(dlep_radio_if, interf.session.cfg.send_neighbors, "not_proxied", "false", "Report direct neighbors"),

  CFG_MAP_INT32_MINMAX(dlep_radio_if, interf.session.cfg.lid_length, "lid_length", DLEP_DEFAULT_LID_LENGTH_TXT,
    "Link-ID length in octets that can be used to communicate with router", 0, 0, OONF_LAYER2_MAX_LINK_ID-1),
};

static struct cfg_schema_section _radio_section = {
  .type = OONF_DLEP_RADIO_SUBSYSTEM,
  .mode = CFG_SSMODE_NAMED,

  .help = "name of the layer2 interface DLEP radio will take its data from",

  .cb_delta_handler = _cb_config_changed,

  .entries = _radio_entries,
  .entry_count = ARRAYSIZE(_radio_entries),
};

/* subsystem declaration */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_PACKET_SUBSYSTEM,
  OONF_STREAM_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
};
static struct oonf_subsystem _dlep_radio_subsystem = {
  .name = OONF_DLEP_RADIO_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONF DLEP radio plugin",
  .author = "Henning Rogge",

  .cfg_section = &_radio_section,

  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .initiate_shutdown = _initiate_shutdown,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_dlep_radio_subsystem);

/* logging */
enum oonf_log_source LOG_DLEP_RADIO;

static void
_early_cfg_init(void) {
  LOG_DLEP_RADIO = _dlep_radio_subsystem.logging;
}

/**
 * Plugin constructor for dlep radio
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  dlep_radio_interface_init();
  return 0;
}

/**
 * Send a clean Peer Terminate before we drop the session to shutdown
 */
static void
_initiate_shutdown(void) {
  dlep_radio_terminate_all_sessions();
}

/**
 * Plugin destructor for dlep radio
 */
static void
_cleanup(void) {
  dlep_radio_interface_cleanup();
}

/**
 * Callback for configuration changes
 */
static void
_cb_config_changed(void) {
  struct dlep_radio_if *interface;
  const char *ifname;
  char ifbuf[IF_NAMESIZE];
  int error;

  ifname = cfg_get_phy_if(ifbuf, _radio_section.section_name);

  if (!_radio_section.post) {
    /* remove old interface object */
    interface = dlep_radio_get_by_layer2_if(ifname);
    if (interface) {
      dlep_radio_remove_interface(interface);
    }
    return;
  }

  /* get interface object or create one */
  interface = dlep_radio_add_interface(ifname);
  if (!interface) {
    return;
  }

  /* read configuration */
  error = cfg_schema_tobin(interface, _radio_section.post, _radio_entries, ARRAYSIZE(_radio_entries));
  if (error) {
    OONF_WARN(LOG_DLEP_RADIO, "Could not convert " OONF_DLEP_RADIO_SUBSYSTEM " config to bin (%d)", error);
    return;
  }

  if (!interface->interf.udp_config.interface[0]) {
    strscpy(interface->interf.udp_config.interface, ifname, IF_NAMESIZE);
  }
  else {
    cfg_get_phy_if(interface->interf.udp_config.interface, interface->interf.udp_config.interface);
  }
  /* apply interface name also to TCP socket */
  strscpy(interface->tcp_config.interface, interface->interf.udp_config.interface, IF_NAMESIZE);

  /* apply settings */
  dlep_radio_apply_interface_settings(interface);
}
