
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

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/template.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_telnet.h>
#include <oonf/base/oonf_viewer.h>

#include <oonf/nhdp/nhdp/nhdp_db.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>
#include <oonf/nhdp/nhdp/nhdp_interfaces.h>

#include <oonf/nhdp/nhdpinfo/nhdpinfo.h>

/* Definitions */
#define LOG_NHDPINFO _olsrv2_nhdpinfo_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static enum oonf_telnet_result _cb_nhdpinfo(struct oonf_telnet_data *con);
static enum oonf_telnet_result _cb_nhdpinfo_help(struct oonf_telnet_data *con);

static void _initialize_interface_values(struct nhdp_interface *nhdp_if);
static void _initialize_interface_address_values(struct nhdp_interface_addr *if_addr);
static void _initialize_nhdp_link_values(struct nhdp_link *lnk);
static void _initialize_nhdp_domain_metric_values(struct nhdp_domain *domain, struct nhdp_metric *metric);
static void _initialize_nhdp_neighbor_mpr_values(
  struct nhdp_domain *domain, struct nhdp_neighbor_domaindata *domaindata);
static void _initialize_nhdp_domain_metric_int_values(struct nhdp_domain *domain, struct nhdp_link *lnk);
static void _initialize_nhdp_link_address_values(struct nhdp_laddr *laddr);
static void _initialize_nhdp_link_twohop_values(struct nhdp_l2hop *twohop);
static void _initialize_nhdp_neighbor_values(struct nhdp_neighbor *neigh);
static void _initialize_nhdp_neighbor_address_values(struct nhdp_naddr *naddr);

static int _cb_create_text_interface(struct oonf_viewer_template *);
static int _cb_create_text_if_address(struct oonf_viewer_template *);
static int _cb_create_text_link(struct oonf_viewer_template *);
static int _cb_create_text_link_address(struct oonf_viewer_template *);
static int _cb_create_text_link_twohop(struct oonf_viewer_template *);
static int _cb_create_text_neighbor(struct oonf_viewer_template *);
static int _cb_create_text_neighbor_address(struct oonf_viewer_template *);

/*
 * list of template keys and corresponding buffers for values.
 *
 * The keys are API, so they should not be changed after published
 */

/*! template key for interface name */
#define KEY_IF "if"

/*! template key for interface IPv4 socket address */
#define KEY_IF_BINDTO_V4 "if_bindto_v4"

/*! template key for interface IPv6 socket address */
#define KEY_IF_BINDTO_V6 "if_bindto_v6"

/*! template key for interface MAP address */
#define KEY_IF_MAC "if_mac"

/*! template key for IPv4 flooding flag */
#define KEY_IF_FLOODING_V4 "if_flooding_v4"

/*! template key for IPv6 flooding flag */
#define KEY_IF_FLOODING_V6 "if_flooding_v6"

/*! template key for dualstack mode */
#define KEY_IF_DUALSTACK_MODE "if_dualstack_mode"

/*! template key for an interface address */
#define KEY_IF_ADDRESS "if_address"

/*! template key for a lost interface address */
#define KEY_IF_ADDRESS_LOST "if_address_lost"

/*! template key for validity time of a lost interface address */
#define KEY_IF_ADDRESS_LOST_VTIME "if_address_lost_vtime"

/*! template key for the links remote socket IP address */
#define KEY_LINK_BINDTO "link_bindto"

/*! template key for the validity time of the link */
#define KEY_LINK_VTIME_VALUE "link_vtime_value"

/*! template key for the interval time of the link */
#define KEY_LINK_ITIME_VALUE "link_itime_value"

/*! template key for the time the link will still be symmetric */
#define KEY_LINK_SYMTIME "link_symtime"

/*! template key for the time the link will still be heard */
#define KEY_LINK_HEARDTIME "link_heardtime"

/*! template key for validity time of the link */
#define KEY_LINK_VTIME "link_vtime"

/*! template key for link status */
#define KEY_LINK_STATUS "link_status"

/*! template key for links local dualstack IP address */
#define KEY_LINK_DUALSTACK "link_dualstack"

/*! template key for links remote mac address */
#define KEY_LINK_MAC "link_mac"

/*! template key signaling link has selected node as flooding MPR */
#define KEY_LINK_FLOOD_LOCAL "link_flood_local"

/*! template key signaling route has selected link as flooding MPR */
#define KEY_LINK_FLOOD_REMOTE "link_flood_remote"

/*! template key for link flooding willingness */
#define KEY_LINK_FLOOD_WILL "link_flood_willingness"

/*! template key for a link IP address */
#define KEY_LINK_ADDRESS "link_address"

/*! template key for an IP address of a two-hop link */
#define KEY_TWOHOP_ADDRESS "twohop_address"

/*! template key for the flag to signal a two-hop link on the same interface */
#define KEY_TWOHOP_SAMEIF "twohop_same_interface"

/*! template key for the validity time of a two-hop link */
#define KEY_TWOHOP_VTIME "twohop_vtime"

/*! template key for neighbors originator IP */
#define KEY_NEIGHBOR_ORIGINATOR "neighbor_originator"

/*! template key for neighbors dualstack originator IP */
#define KEY_NEIGHBOR_DUALSTACK "neighbor_dualstack"

/*! template key for number of symmetric links of neighbor */
#define KEY_NEIGHBOR_SYMMETRIC "neighbor_symmetric"

/*! template key for number of links of neighbor */
#define KEY_NEIGHBOR_LINKCOUNT "neighbor_linkcount"

/*! template key for neighbor address */
#define KEY_NEIGHBOR_ADDRESS "neighbor_address"

/*! template key for lost neighbor address */
#define KEY_NEIGHBOR_ADDRESS_LOST "neighbor_address_lost"

/*! template key for validity time of lost neighbor address */
#define KEY_NEIGHBOR_ADDRESS_VTIME "neighbor_address_lost_vtime"

/*! template key for NHDP domain */
#define KEY_DOMAIN "domain"

/*! template key for NHDP domain metric name */
#define KEY_DOMAIN_METRIC "domain_metric"

/*! template key for incoming human readable metric */
#define KEY_DOMAIN_METRIC_IN "domain_metric_in"

/*! template key for outgoing human readable metric */
#define KEY_DOMAIN_METRIC_OUT "domain_metric_out"

/*! template key for incoming numeric metric */
#define KEY_DOMAIN_METRIC_IN_RAW "domain_metric_in_raw"

/*! template key for outgoing numeric metric */
#define KEY_DOMAIN_METRIC_OUT_RAW "domain_metric_out_raw"

/*! template key for internal metric representation */
#define KEY_DOMAIN_METRIC_INTERNAL "domain_metric_internal"

/*! template key for NHDP domain MPR name */
#define KEY_DOMAIN_MPR "domain_mpr"

/*! template key signaling local node is selected as routing MPR */
#define KEY_DOMAIN_MPR_LOCAL "domain_mpr_local"

/*! template key signaling remote node has been selected as routing MPR */
#define KEY_DOMAIN_MPR_REMOTE "domain_mpr_remote"

/*! template key for routing willingness */
#define KEY_DOMAIN_MPR_WILL "domain_mpr_willingness"

/*
 * buffer space for values that will be assembled
 * into the output of the plugin
 */
static char _value_if[IF_NAMESIZE];
static struct netaddr_str _value_if_bindto_v4;
static struct netaddr_str _value_if_bindto_v6;
static struct netaddr_str _value_if_mac;
static char _value_if_flooding_v4[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_if_flooding_v6[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_if_dualstack_mode[5];
static struct netaddr_str _value_if_address;
static char _value_if_address_lost[TEMPLATE_JSON_BOOL_LENGTH];
static struct isonumber_str _value_if_address_vtime;

static struct netaddr_str _value_link_bindto;
static struct isonumber_str _value_link_vtime_value;
static struct isonumber_str _value_link_itime_value;
static struct isonumber_str _value_link_symtime;
static struct isonumber_str _value_link_heardtime;
static struct isonumber_str _value_link_vtime;
static char _value_link_status[NHDP_LINK_STATUS_TXTLENGTH];
static struct netaddr_str _value_link_dualstack;
static struct netaddr_str _value_link_mac;
static char _value_link_flood_local[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_link_flood_remote[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_link_willingness[3];

static struct netaddr_str _value_link_address;

static struct netaddr_str _value_twohop_address;
static char _value_twohop_sameif[TEMPLATE_JSON_BOOL_LENGTH];
static struct isonumber_str _value_twohop_vtime;

static struct netaddr_str _value_neighbor_originator;
static struct netaddr_str _value_neighbor_dualstack;
static char _value_neighbor_symmetric[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_neighbor_linkcount[10];
static struct netaddr_str _value_neighbor_address;
static char _value_neighbor_address_lost[TEMPLATE_JSON_BOOL_LENGTH];
static struct isonumber_str _value_neighbor_address_lost_vtime;

static char _value_domain[4];
static char _value_domain_metric[NHDP_DOMAIN_METRIC_MAXLEN];
static struct nhdp_metric_str _value_domain_metric_in;
static struct nhdp_metric_str _value_domain_metric_out;
static char _value_domain_metric_in_raw[12];
static char _value_domain_metric_out_raw[12];
static struct nhdp_metric_str _value_domain_metric_internal;
static char _value_domain_mpr[NHDP_DOMAIN_MPR_MAXLEN];
static char _value_domain_mpr_local[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_domain_mpr_remote[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_domain_mpr_will[3];

/* definition of the template data entries for JSON and table output */
static struct abuf_template_data_entry _tde_if_key[] = {
  { KEY_IF, _value_if, true },
};

static struct abuf_template_data_entry _tde_if[] = {
  { KEY_IF, _value_if, true },
  { KEY_IF_BINDTO_V4, _value_if_bindto_v4.buf, true },
  { KEY_IF_BINDTO_V6, _value_if_bindto_v6.buf, true },
  { KEY_IF_MAC, _value_if_mac.buf, true },
  { KEY_IF_FLOODING_V4, _value_if_flooding_v4, true },
  { KEY_IF_FLOODING_V6, _value_if_flooding_v6, true },
  { KEY_IF_DUALSTACK_MODE, _value_if_dualstack_mode, true },
};

static struct abuf_template_data_entry _tde_if_addr[] = {
  { KEY_IF_ADDRESS, _value_if_address.buf, true },
  { KEY_IF_ADDRESS_LOST, _value_if_address_lost, true },
  { KEY_IF_ADDRESS_LOST_VTIME, _value_if_address_vtime.buf, false },
};

static struct abuf_template_data_entry _tde_link_key[] = {
  { KEY_LINK_BINDTO, _value_link_bindto.buf, true },
  { KEY_NEIGHBOR_ORIGINATOR, _value_neighbor_originator.buf, true },
};

static struct abuf_template_data_entry _tde_link[] = {
  { KEY_LINK_BINDTO, _value_link_bindto.buf, true },
  { KEY_LINK_VTIME_VALUE, _value_link_vtime_value.buf, false },
  { KEY_LINK_ITIME_VALUE, _value_link_itime_value.buf, false },
  { KEY_LINK_SYMTIME, _value_link_symtime.buf, false },
  { KEY_LINK_HEARDTIME, _value_link_heardtime.buf, false },
  { KEY_LINK_VTIME, _value_link_vtime.buf, false },
  { KEY_LINK_STATUS, _value_link_status, true },
  { KEY_LINK_DUALSTACK, _value_link_dualstack.buf, true },
  { KEY_LINK_MAC, _value_link_mac.buf, true },
  { KEY_LINK_FLOOD_LOCAL, _value_link_flood_local, true },
  { KEY_LINK_FLOOD_REMOTE, _value_link_flood_remote, true },
  { KEY_LINK_FLOOD_WILL, _value_link_willingness, false },
  { KEY_NEIGHBOR_ORIGINATOR, _value_neighbor_originator.buf, true },
  { KEY_NEIGHBOR_DUALSTACK, _value_neighbor_dualstack.buf, true },
};

static struct abuf_template_data_entry _tde_domain[] = {
  { KEY_DOMAIN, _value_domain, false },
};

static struct abuf_template_data_entry _tde_domain_metric[] = {
  { KEY_DOMAIN_METRIC, _value_domain_metric, true },
  { KEY_DOMAIN_METRIC_IN, _value_domain_metric_in.buf, true },
  { KEY_DOMAIN_METRIC_IN_RAW, _value_domain_metric_in_raw, false },
  { KEY_DOMAIN_METRIC_OUT, _value_domain_metric_out.buf, true },
  { KEY_DOMAIN_METRIC_OUT_RAW, _value_domain_metric_out_raw, false },
};
static struct abuf_template_data_entry _tde_domain_metric_int[] = {
  { KEY_DOMAIN_METRIC_INTERNAL, _value_domain_metric_internal.buf, true },
};

static struct abuf_template_data_entry _tde_domain_mpr[] = {
  { KEY_DOMAIN_MPR, _value_domain_mpr, true },
  { KEY_DOMAIN_MPR_LOCAL, _value_domain_mpr_local, true },
  { KEY_DOMAIN_MPR_REMOTE, _value_domain_mpr_remote, true },
  { KEY_DOMAIN_MPR_WILL, _value_domain_mpr_will, false },
};

static struct abuf_template_data_entry _tde_link_addr[] = {
  { KEY_LINK_ADDRESS, _value_link_address.buf, true },
};

static struct abuf_template_data_entry _tde_twohop_addr[] = {
  { KEY_TWOHOP_ADDRESS, _value_twohop_address.buf, true },
  { KEY_TWOHOP_SAMEIF, _value_twohop_sameif, true },
  { KEY_TWOHOP_VTIME, _value_twohop_vtime.buf, false },
};

static struct abuf_template_data_entry _tde_neigh_key[] = {
  { KEY_NEIGHBOR_ORIGINATOR, _value_neighbor_originator.buf, true },
};

static struct abuf_template_data_entry _tde_neigh[] = {
  { KEY_NEIGHBOR_DUALSTACK, _value_neighbor_dualstack.buf, true },
  { KEY_NEIGHBOR_SYMMETRIC, _value_neighbor_symmetric, true },
  { KEY_NEIGHBOR_LINKCOUNT, _value_neighbor_linkcount, false },
};

static struct abuf_template_data_entry _tde_neigh_addr[] = {
  { KEY_NEIGHBOR_ADDRESS, _value_neighbor_address.buf, true },
  { KEY_NEIGHBOR_ADDRESS_LOST, _value_neighbor_address_lost, true },
  { KEY_NEIGHBOR_ADDRESS_VTIME, _value_neighbor_address_lost_vtime.buf, false },
};

static struct abuf_template_storage _template_storage;

/* Template Data objects (contain one or more Template Data Entries) */
static struct abuf_template_data _td_if[] = {
  { _tde_if, ARRAYSIZE(_tde_if) },
};
static struct abuf_template_data _td_if_addr[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_if_addr, ARRAYSIZE(_tde_if_addr) },
};
static struct abuf_template_data _td_link[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_link, ARRAYSIZE(_tde_link) },
  { _tde_domain, ARRAYSIZE(_tde_domain) },
  { _tde_domain_metric, ARRAYSIZE(_tde_domain_metric) },
  { _tde_domain_metric_int, ARRAYSIZE(_tde_domain_metric_int) },
};
static struct abuf_template_data _td_link_addr[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_link_key, ARRAYSIZE(_tde_link_key) },
  { _tde_link_addr, ARRAYSIZE(_tde_link_addr) },
};
static struct abuf_template_data _td_twohop_addr[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_link_key, ARRAYSIZE(_tde_link_key) },
  { _tde_twohop_addr, ARRAYSIZE(_tde_twohop_addr) },
  { _tde_domain_metric, ARRAYSIZE(_tde_domain_metric) },
};
static struct abuf_template_data _td_neigh[] = {
  { _tde_neigh_key, ARRAYSIZE(_tde_neigh_key) },
  { _tde_neigh, ARRAYSIZE(_tde_neigh) },
  { _tde_domain, ARRAYSIZE(_tde_domain) },
  { _tde_domain_metric, ARRAYSIZE(_tde_domain_metric) },
  { _tde_domain_mpr, ARRAYSIZE(_tde_domain_mpr) },
};
static struct abuf_template_data _td_neigh_addr[] = {
  { _tde_neigh_key, ARRAYSIZE(_tde_neigh_key) },
  { _tde_neigh_addr, ARRAYSIZE(_tde_neigh_addr) },
};

/* OONF viewer templates (based on Template Data arrays) */
static struct oonf_viewer_template _templates[] = { {
                                                      .data = _td_if,
                                                      .data_size = ARRAYSIZE(_td_if),
                                                      .json_name = "interface",
                                                      .cb_function = _cb_create_text_interface,
                                                    },
  {
    .data = _td_if_addr,
    .data_size = ARRAYSIZE(_td_if_addr),
    .json_name = "if_addr",
    .cb_function = _cb_create_text_if_address,
  },
  {
    .data = _td_link,
    .data_size = ARRAYSIZE(_td_link),
    .json_name = "link",
    .cb_function = _cb_create_text_link,
  },
  {
    .data = _td_link_addr,
    .data_size = ARRAYSIZE(_td_link_addr),
    .json_name = "link_addr",
    .cb_function = _cb_create_text_link_address,
  },
  {
    .data = _td_twohop_addr,
    .data_size = ARRAYSIZE(_td_twohop_addr),
    .json_name = "link_twohop",
    .cb_function = _cb_create_text_link_twohop,
  },
  {
    .data = _td_neigh,
    .data_size = ARRAYSIZE(_td_neigh),
    .json_name = "neighbor",
    .cb_function = _cb_create_text_neighbor,
  },
  {
    .data = _td_neigh_addr,
    .data_size = ARRAYSIZE(_td_neigh_addr),
    .json_name = "neighbor_addr",
    .cb_function = _cb_create_text_neighbor_address,
  } };

/* telnet command of this plugin */
static struct oonf_telnet_command _telnet_commands[] = {
  TELNET_CMD(OONF_NHDPINFO_SUBSYSTEM, _cb_nhdpinfo, "", .help_handler = _cb_nhdpinfo_help),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
  OONF_VIEWER_SUBSYSTEM,
  OONF_NHDP_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_nhdpinfo_subsystem = {
  .name = OONF_NHDPINFO_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "NHDPinfo plugin",
  .author = "Henning Rogge",
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_olsrv2_nhdpinfo_subsystem);

/**
 * Initialize plugin
 * @return always returns 0
 */
static int
_init(void) {
  oonf_telnet_add(&_telnet_commands[0]);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  oonf_telnet_remove(&_telnet_commands[0]);
}

/**
 * Callback for the telnet command of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_nhdpinfo(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_handler(
    con->out, &_template_storage, OONF_NHDPINFO_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Callback for the help output of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_nhdpinfo_help(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_help(con->out, OONF_NHDPINFO_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Initialize the value buffers for a NHDP interface
 * @param nhdp_if nhdp interface
 */
static void
_initialize_interface_values(struct nhdp_interface *nhdp_if) {
  struct os_interface_listener *if_listener;
  struct netaddr temp_addr;

  if_listener = nhdp_interface_get_if_listener(nhdp_if);

  /* fill output buffers for template engine */
  strscpy(_value_if, nhdp_interface_get_name(nhdp_if), sizeof(_value_if));

  netaddr_from_socket(&temp_addr, &nhdp_if->rfc5444_if.interface->_socket.socket_v4.local_socket);
  netaddr_to_string(&_value_if_bindto_v4, &temp_addr);

  netaddr_from_socket(&temp_addr, &nhdp_if->rfc5444_if.interface->_socket.socket_v6.local_socket);
  netaddr_to_string(&_value_if_bindto_v6, &temp_addr);

  netaddr_to_string(&_value_if_mac, &if_listener->data->mac);

  strscpy(_value_if_flooding_v4, json_getbool(nhdp_if->use_ipv4_for_flooding), TEMPLATE_JSON_BOOL_LENGTH);

  strscpy(_value_if_flooding_v6, json_getbool(nhdp_if->use_ipv6_for_flooding), TEMPLATE_JSON_BOOL_LENGTH);

  if (nhdp_if->dualstack_af_type == AF_INET) {
    strscpy(_value_if_dualstack_mode, "IPv4", sizeof(_value_if_dualstack_mode));
  }
  else if (nhdp_if->dualstack_af_type == AF_INET6) {
    strscpy(_value_if_dualstack_mode, "IPv6", sizeof(_value_if_dualstack_mode));
  }
  else {
    strscpy(_value_if_dualstack_mode, "-", sizeof(_value_if_dualstack_mode));
  }
}

/**
 * Initialize the value buffers for a NHDP interface address
 * @param if_addr interface NHDP address
 */
static void
_initialize_interface_address_values(struct nhdp_interface_addr *if_addr) {
  netaddr_to_string(&_value_if_address, &if_addr->if_addr);

  strscpy(_value_if_address_lost, json_getbool(if_addr->removed), sizeof(_value_if_address_lost));
  oonf_timer_to_string(&_value_if_address_vtime, &if_addr->_vtime);
}

/**
 * Initialize the value buffers for a NHDP link
 * @param lnk NHDP link
 */
static void
_initialize_nhdp_link_values(struct nhdp_link *lnk) {
  netaddr_to_string(&_value_link_bindto, &lnk->if_addr);

  oonf_clock_toIntervalString(&_value_link_vtime_value, lnk->vtime_value);
  oonf_clock_toIntervalString(&_value_link_itime_value, lnk->itime_value);

  oonf_timer_to_string(&_value_link_symtime, &lnk->sym_time);
  oonf_timer_to_string(&_value_link_heardtime, &lnk->heard_time);
  oonf_timer_to_string(&_value_link_vtime, &lnk->vtime);

  strscpy(_value_link_status, nhdp_db_link_status_to_string(lnk), sizeof(_value_link_status));

  if (lnk->dualstack_partner) {
    netaddr_to_string(&_value_link_dualstack, &lnk->dualstack_partner->if_addr);
  }
  else {
    strscpy(_value_link_dualstack.buf, "-", sizeof(_value_link_dualstack));
  }

  netaddr_to_string(&_value_link_mac, &lnk->remote_mac);

  strscpy(_value_link_flood_local, json_getbool(lnk->local_is_flooding_mpr), sizeof(_value_link_flood_local));
  strscpy(_value_link_flood_remote, json_getbool(lnk->neigh_is_flooding_mpr), sizeof(_value_link_flood_remote));
  snprintf(_value_link_willingness, sizeof(_value_link_willingness), "%u", lnk->flooding_willingness & 15);
}

/**
 * Initialize the value buffers for NHDP domain metric values
 * @param domain NHDP domain
 * @param metric NHDP metric
 */
static void
_initialize_nhdp_domain_metric_values(struct nhdp_domain *domain, struct nhdp_metric *metric) {
  snprintf(_value_domain, sizeof(_value_domain), "%u", domain->ext);
  strscpy(_value_domain_metric, domain->metric->name, sizeof(_value_domain_metric));

  nhdp_domain_get_link_metric_value(&_value_domain_metric_in, domain, metric->in);
  nhdp_domain_get_link_metric_value(&_value_domain_metric_out, domain, metric->out);

  snprintf(_value_domain_metric_in_raw, sizeof(_value_domain_metric_in_raw), "%u", metric->in);
  snprintf(_value_domain_metric_out_raw, sizeof(_value_domain_metric_out_raw), "%u", metric->out);
}

/**
 * Initialize the value buffers for a NHDP domain MPR values
 * @param domain NHDP domain
 * @param domaindata NHDP neighbor domain data
 */
static void
_initialize_nhdp_neighbor_mpr_values(struct nhdp_domain *domain, struct nhdp_neighbor_domaindata *domaindata) {
  snprintf(_value_domain, sizeof(_value_domain), "%u", domain->ext);
  strscpy(_value_domain_mpr, domain->mpr->name, sizeof(_value_domain_mpr));

  strscpy(_value_domain_mpr_local, json_getbool(domaindata->local_is_mpr), sizeof(_value_domain_mpr_local));

  strscpy(_value_domain_mpr_remote, json_getbool(domaindata->neigh_is_mpr), sizeof(_value_domain_mpr_remote));

  snprintf(_value_domain_mpr_will, sizeof(_value_domain_mpr_will), "%1u", domaindata->willingness & 15);
}

static void
_initialize_nhdp_domain_metric_int_values(struct nhdp_domain *domain, struct nhdp_link *lnk) {
  nhdp_domain_get_internal_link_metric_value(&_value_domain_metric_internal, domain->metric, lnk);
}

/**
 * Initialize the value buffers for a NHDP link address
 * @param laddr NHDP link address
 */
static void
_initialize_nhdp_link_address_values(struct nhdp_laddr *laddr) {
  netaddr_to_string(&_value_link_address, &laddr->link_addr);
}

/**
 * Initialize the value buffers for a NHDP link twohop address
 * @param twohop NHDP twohop address
 */
static void
_initialize_nhdp_link_twohop_values(struct nhdp_l2hop *twohop) {
  netaddr_to_string(&_value_twohop_address, &twohop->twohop_addr);

  strscpy(_value_twohop_sameif, json_getbool(twohop->same_interface), sizeof(_value_twohop_sameif));

  oonf_timer_to_string(&_value_twohop_vtime, &twohop->_vtime);
}

/**
 * Initialize the value buffers for a NHDP neighbor
 * @param neigh NHDP neighbor
 */
static void
_initialize_nhdp_neighbor_values(struct nhdp_neighbor *neigh) {
  netaddr_to_string(&_value_neighbor_originator, &neigh->originator);
  if (neigh->dualstack_partner) {
    netaddr_to_string(&_value_neighbor_dualstack, &neigh->dualstack_partner->originator);
  }
  else {
    strscpy(_value_neighbor_dualstack.buf, "-", sizeof(_value_neighbor_dualstack));
  }

  strscpy(_value_neighbor_symmetric, json_getbool(neigh->symmetric > 0), sizeof(_value_neighbor_symmetric));
  snprintf(_value_neighbor_linkcount, sizeof(_value_neighbor_linkcount), "%d", neigh->symmetric);
}

/**
 * Initialize the value buffers for a NHDP neighbor address
 * @param naddr NHDP neighbor address
 */
static void
_initialize_nhdp_neighbor_address_values(struct nhdp_naddr *naddr) {
  netaddr_to_string(&_value_neighbor_address, &naddr->neigh_addr);

  strscpy(_value_neighbor_address_lost, json_getbool(oonf_timer_is_active(&naddr->_lost_vtime)),
    sizeof(_value_neighbor_address_lost));

  oonf_timer_to_string(&_value_neighbor_address_lost_vtime, &naddr->_lost_vtime);
}

/**
 * Displays the known data about each NHDP interface.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_interface(struct oonf_viewer_template *template) {
  struct nhdp_interface *nhdpif;

  avl_for_each_element(nhdp_interface_get_tree(), nhdpif, _node) {
    _initialize_interface_values(nhdpif);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Displays the addresses of a NHDP interface.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_if_address(struct oonf_viewer_template *template) {
  struct nhdp_interface *nhdp_if;
  struct nhdp_interface_addr *nhdp_addr;

  avl_for_each_element(nhdp_interface_get_tree(), nhdp_if, _node) {
    /* fill output buffers for template engine */
    _initialize_interface_values(nhdp_if);

    avl_for_each_element(&nhdp_if->_if_addresses, nhdp_addr, _if_node) {
      /* fill address specific output buffers for template engine */
      _initialize_interface_address_values(nhdp_addr);

      /* generate template output */
      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}

/**
 * Displays the data of a NHDP link.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_link(struct oonf_viewer_template *template) {
  struct nhdp_interface *nhdp_if;
  struct nhdp_link *nlink;
  struct nhdp_domain *domain;

  avl_for_each_element(nhdp_interface_get_tree(), nhdp_if, _node) {
    /* fill output buffers for template engine */
    _initialize_interface_values(nhdp_if);

    list_for_each_element(&nhdp_if->_links, nlink, _if_node) {
      _initialize_nhdp_link_values(nlink);
      _initialize_nhdp_neighbor_values(nlink->neigh);

      list_for_each_element(nhdp_domain_get_list(), domain, _node) {
        _initialize_nhdp_domain_metric_values(domain, &(nhdp_domain_get_linkdata(domain, nlink)->metric));
        _initialize_nhdp_domain_metric_int_values(domain, nlink);

        /* generate template output */
        oonf_viewer_output_print_line(template);
      }
    }
  }
  return 0;
}

/**
 * Displays the addresses of a NHDP link.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_link_address(struct oonf_viewer_template *template) {
  struct nhdp_interface *nhdpif;
  struct nhdp_link *nhdplink;
  struct nhdp_laddr *laddr;

  avl_for_each_element(nhdp_interface_get_tree(), nhdpif, _node) {
    /* fill output buffers for template engine */
    _initialize_interface_values(nhdpif);

    list_for_each_element(&nhdpif->_links, nhdplink, _if_node) {
      _initialize_nhdp_link_values(nhdplink);
      _initialize_nhdp_neighbor_values(nhdplink->neigh);

      avl_for_each_element(&nhdplink->_addresses, laddr, _link_node) {
        _initialize_nhdp_link_address_values(laddr);

        /* generate template output */
        oonf_viewer_output_print_line(template);
      }
    }
  }
  return 0;
}

/**
 * Displays the twohop neighbors of a NHDP link.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_link_twohop(struct oonf_viewer_template *template) {
  struct nhdp_interface *nhdpif;
  struct nhdp_link *nhdplink;
  struct nhdp_l2hop *twohop;
  struct nhdp_domain *domain;

  avl_for_each_element(nhdp_interface_get_tree(), nhdpif, _node) {
    /* fill output buffers for template engine */
    _initialize_interface_values(nhdpif);

    list_for_each_element(&nhdpif->_links, nhdplink, _if_node) {
      _initialize_nhdp_link_values(nhdplink);
      _initialize_nhdp_neighbor_values(nhdplink->neigh);

      avl_for_each_element(&nhdplink->_2hop, twohop, _link_node) {
        _initialize_nhdp_link_twohop_values(twohop);

        list_for_each_element(nhdp_domain_get_list(), domain, _node) {
          _initialize_nhdp_domain_metric_values(domain, &nhdp_domain_get_l2hopdata(domain, twohop)->metric);

          /* generate template output */
          oonf_viewer_output_print_line(template);
        }
      }
    }
  }
  return 0;
}

/**
 * Displays the data of a NHDP neighbor.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_neighbor(struct oonf_viewer_template *template) {
  struct nhdp_neighbor *neigh;
  struct nhdp_domain *domain;

  list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
    _initialize_nhdp_neighbor_values(neigh);

    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      struct nhdp_neighbor_domaindata *data;

      data = nhdp_domain_get_neighbordata(domain, neigh);

      _initialize_nhdp_domain_metric_values(domain, &data->metric);
      _initialize_nhdp_neighbor_mpr_values(domain, data);

      /* generate template output */
      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}

/**
 * Displays the addresses of a NHDP neighbor.
 * @param template oonf viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_neighbor_address(struct oonf_viewer_template *template) {
  struct nhdp_neighbor *neigh;
  struct nhdp_naddr *naddr;

  list_for_each_element(nhdp_db_get_neigh_list(), neigh, _global_node) {
    _initialize_nhdp_neighbor_values(neigh);

    avl_for_each_element(&neigh->_neigh_addresses, naddr, _neigh_node) {
      _initialize_nhdp_neighbor_address_values(naddr);

      /* generate template output */
      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}
