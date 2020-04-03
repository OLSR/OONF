
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

#include <stdio.h>

#include <oonf/libcommon/autobuf.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libcommon/string.h>
#include <oonf/libcommon/template.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_telnet.h>
#include <oonf/base/oonf_viewer.h>

#include <oonf/generic/layer2info/layer2info.h>

/* definitions */
#define LOG_LAYER2INFO _oonf_layer2info_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static enum oonf_telnet_result _cb_layer2info(struct oonf_telnet_data *con);
static enum oonf_telnet_result _cb_layer2info_help(struct oonf_telnet_data *con);

static void _initialize_if_data_values(struct oonf_viewer_template *template, struct oonf_layer2_net *l2net);
static void _initialize_if_default_data_values(struct oonf_viewer_template *template, struct oonf_layer2_net *l2net);
static void _initialize_if_origin_values(struct oonf_layer2_data *data);
static void _initialize_if_values(struct oonf_layer2_net *net);
static void _initialize_if_ip_values(struct oonf_layer2_peer_address *peer_ip);

static void _initialize_neigh_data_values(struct oonf_viewer_template *template, struct oonf_layer2_neigh *l2neigh);
static void _initialize_neigh_origin_values(struct oonf_layer2_data *data);
static void _initialize_neigh_values(struct oonf_layer2_neigh *neigh);
static void _initialize_neigh_ip_values(struct oonf_layer2_neighbor_address *neigh_addr);
static void _initialize_origin_values(struct oonf_layer2_origin *l2origin);

static int _cb_create_text_interface(struct oonf_viewer_template *);
static int _cb_create_text_interface_ip(struct oonf_viewer_template *);
static int _cb_create_text_neighbor(struct oonf_viewer_template *);
static int _cb_create_text_neighbor_ip(struct oonf_viewer_template *);
static int _cb_create_text_default(struct oonf_viewer_template *);
static int _cb_create_text_dst(struct oonf_viewer_template *);
static int _cb_create_text_origin(struct oonf_viewer_template *);

/*
 * list of template keys and corresponding buffers for values.
 *
 * The keys are API, so they should not be changed after published
 */

/*! template key for interface name */
#define KEY_IF "if"

/*! template key for interface index */
#define KEY_IF_INDEX "if_index"

/*! template key for interface type */
#define KEY_IF_TYPE "if_type"

/*! template key for DLEP interface */
#define KEY_IF_DLEP "if_dlep"

/*! template key for interface identifier */
#define KEY_IF_IDENT "if_ident"

/*! template key for interface address identifier */
#define KEY_IF_IDENT_ADDR "if_ident_addr"

/*! template key for local interface address */
#define KEY_IF_LOCAL_ADDR "if_local_addr"

/*! template key for last time interface was active */
#define KEY_IF_LASTSEEN "if_lastseen"

/*! template key for IP/prefixes of the local radio/model */
#define KEY_IF_PEER_IP "if_peer_ip"

/*! template key for IP/prefixes origin of the local radio/model */
#define KEY_IF_PEER_IP_ORIGIN "if_peer_ip_origin"

/*! template key for neighbor address */
#define KEY_NEIGH_ADDR "neigh_addr"

/*! template key for neighbor link-id */
#define KEY_NEIGH_LID "neigh_lid"

/*! template key for neighbor link-id length */
#define KEY_NEIGH_LID_LEN "neigh_lid_length"

/*! template key for neighbor IPv4 next hop */
#define KEY_NEIGH_NEXTHOP_V4 "neigh_nexthop_v4"

/*! template key for neighbor IPv4 next hop */
#define KEY_NEIGH_NEXTHOP_V6 "neigh_nexthop_v6"

/*! template key for last time neighbor was active */
#define KEY_NEIGH_LASTSEEN "neigh_lastseen"

/*! template key for IP/prefixes of the neighbors remote router */
#define KEY_NEIGH_REMOTE_IP "neigh_remote_ip"

/*! template key for neighbors IP next hop */
#define KEY_NEIGH_REMOTE_NEXTHOP "neigh_remote_ip_nexthop"

/*! template key for IP/prefixes origin of the neighbors remote router */
#define KEY_NEIGH_REMOTE_IP_ORIGIN "neigh_remote_ip_origin"

/*! template key for destination address */
#define KEY_DST_ADDR "dst_addr"

/*! template key for destination origin */
#define KEY_DST_ORIGIN "dst_origin"

/*! string prefix for all interface keys */
#define KEY_IF_PREFIX "if_"

/*! string prefix for all neighbor keys */
#define KEY_NEIGH_PREFIX "neigh_"

/*! string suffix for all data originators */
#define KEY_ORIGIN_SUFFIX "_origin"

/*! template key for originator name */
#define KEY_ORIGIN_NAME       "origin_name"

/*! template key for origin is proactive */
#define KEY_ORIGIN_PROACTIVE "origin_proactive"

/*! template key for origin priority */
#define KEY_ORIGIN_PRIORITY  "origin_priority"

/*! template key for origin produces LIDs */
#define KEY_ORIGIN_LID       "origin_lid"

/*! template key for origin LID index */
#define KEY_ORIGIN_LID_INDEX "origin_lid_index"

/*
 * buffer space for values that will be assembled
 * into the output of the plugin
 */
static char _value_if[IF_NAMESIZE];
static char _value_if_index[12];
static char _value_if_type[16];
static char _value_if_dlep[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_if_ident[33];
static struct netaddr_str _value_if_ident_addr;
static struct netaddr_str _value_if_local_addr;
static struct isonumber_str _value_if_lastseen;
static struct netaddr_str _value_if_peer_ip;
static char _value_if_peer_ip_origin[IF_NAMESIZE];
static char _value_if_data[OONF_LAYER2_NET_COUNT][64];
static char _value_if_origin[OONF_LAYER2_NET_COUNT][IF_NAMESIZE];
static struct netaddr_str _value_neigh_addr;
static union oonf_layer2_neigh_key_str _value_neigh_key;
static struct netaddr_str _value_neigh_nexthop_v4;
static struct netaddr_str _value_neigh_nexthop_v6;
static char _value_neigh_key_length[6];
static struct isonumber_str _value_neigh_lastseen;
static struct netaddr_str _value_neigh_remote_ip;
static struct netaddr_str _value_neigh_remote_ip_nexthop;
static char _value_neigh_remote_ip_origin[IF_NAMESIZE];
static char _value_neigh_data[OONF_LAYER2_NEIGH_COUNT][64];
static char _value_neigh_origin[OONF_LAYER2_NEIGH_COUNT][IF_NAMESIZE];
static struct netaddr_str _value_dst_addr;
static char _value_dst_origin[IF_NAMESIZE];
static char _value_origin_name[IF_NAMESIZE];
static char _value_origin_proactive[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_origin_priority[10];
static char _value_origin_lid[TEMPLATE_JSON_BOOL_LENGTH];
static char _value_origin_lid_index[10];

/* definition of the template data entries for JSON and table output */
static struct abuf_template_data_entry _tde_if_key[] = {
  { KEY_IF, _value_if, true },
  { KEY_IF_INDEX, _value_if_index, false },
  { KEY_IF_LOCAL_ADDR, _value_if_local_addr.buf, true },
};

static struct abuf_template_data_entry _tde_if[] = {
  { KEY_IF_TYPE, _value_if_type, true },
  { KEY_IF_DLEP, _value_if_dlep, true },
  { KEY_IF_IDENT, _value_if_ident, true },
  { KEY_IF_IDENT_ADDR, _value_if_ident_addr.buf, true },
  { KEY_IF_LASTSEEN, _value_if_lastseen.buf, false },
};

static struct abuf_template_data_entry _tde_if_peer_ip[] = {
  { KEY_IF_PEER_IP, _value_if_peer_ip.buf, true },
  { KEY_IF_PEER_IP_ORIGIN, _value_if_peer_ip_origin, true },
};

static struct abuf_template_data_entry _tde_if_data[OONF_LAYER2_NET_COUNT];
static struct abuf_template_data_entry _tde_if_origin[OONF_LAYER2_NET_COUNT];

static struct abuf_template_data_entry _tde_neigh_key[] = {
  { KEY_NEIGH_ADDR, _value_neigh_addr.buf, true },
  { KEY_NEIGH_LID, _value_neigh_key.buf, true },
  { KEY_NEIGH_LID_LEN, _value_neigh_key_length, false },
};

static struct abuf_template_data_entry _tde_neigh[] = {
  { KEY_NEIGH_NEXTHOP_V4, _value_neigh_nexthop_v4.buf, true },
  { KEY_NEIGH_NEXTHOP_V6, _value_neigh_nexthop_v6.buf, true },
  { KEY_NEIGH_LASTSEEN, _value_neigh_lastseen.buf, false },
};

static struct abuf_template_data_entry _tde_neigh_remote_ip[] = {
  { KEY_NEIGH_REMOTE_IP, _value_neigh_remote_ip.buf, true },
  { KEY_NEIGH_REMOTE_NEXTHOP, _value_neigh_remote_ip_nexthop.buf, true },
  { KEY_NEIGH_REMOTE_IP_ORIGIN, _value_neigh_remote_ip_origin, true },
};

static struct abuf_template_data_entry _tde_neigh_data[OONF_LAYER2_NEIGH_COUNT];
static struct abuf_template_data_entry _tde_neigh_origin[OONF_LAYER2_NEIGH_COUNT];

static struct abuf_template_data_entry _tde_dst_key[] = {
  { KEY_DST_ADDR, _value_dst_addr.buf, true },
};
static struct abuf_template_data_entry _tde_dst[] = {
  { KEY_DST_ORIGIN, _value_dst_origin, true },
};

static struct abuf_template_data_entry _tde_origin[] = {
  { KEY_ORIGIN_NAME, _value_origin_name, true },
  { KEY_ORIGIN_PROACTIVE, _value_origin_proactive, true },
  { KEY_ORIGIN_PRIORITY, _value_origin_priority, false },
  { KEY_ORIGIN_LID, _value_origin_lid, true },
  { KEY_ORIGIN_LID_INDEX, _value_origin_lid_index, false },
};

static struct abuf_template_storage _template_storage;
static struct autobuf _key_storage;

/* Template Data objects (contain one or more Template Data Entries) */
static struct abuf_template_data _td_if[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_if, ARRAYSIZE(_tde_if) },
  { _tde_if_data, ARRAYSIZE(_tde_if_data) },
  { _tde_if_origin, ARRAYSIZE(_tde_if_origin) },
};
static struct abuf_template_data _td_if_ips[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_if_peer_ip, ARRAYSIZE(_tde_if_peer_ip) },
};
static struct abuf_template_data _td_neigh[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_neigh_key, ARRAYSIZE(_tde_neigh_key) },
  { _tde_neigh, ARRAYSIZE(_tde_neigh) },
  { _tde_neigh_data, ARRAYSIZE(_tde_neigh_data) },
  { _tde_neigh_origin, ARRAYSIZE(_tde_neigh_origin) },
};
static struct abuf_template_data _td_neigh_ips[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_neigh_key, ARRAYSIZE(_tde_neigh_key) },
  { _tde_neigh_remote_ip, ARRAYSIZE(_tde_neigh_remote_ip) },
};
static struct abuf_template_data _td_default[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_neigh_data, ARRAYSIZE(_tde_neigh_data) },
  { _tde_neigh_origin, ARRAYSIZE(_tde_neigh_origin) },
};
static struct abuf_template_data _td_dst[] = {
  { _tde_if_key, ARRAYSIZE(_tde_if_key) },
  { _tde_neigh_key, ARRAYSIZE(_tde_neigh_key) },
  { _tde_dst_key, ARRAYSIZE(_tde_dst_key) },
  { _tde_dst, ARRAYSIZE(_tde_dst) },
};
static struct abuf_template_data _td_origin[] = {
  { _tde_origin, ARRAYSIZE(_tde_origin) },
};

/* OONF viewer templates (based on Template Data arrays) */
static struct oonf_viewer_template _templates[] = {
  {
    .data = _td_if,
    .data_size = ARRAYSIZE(_td_if),
    .json_name = "interface",
    .cb_function = _cb_create_text_interface,
  },
  {
    .data = _td_if_ips,
    .data_size = ARRAYSIZE(_td_if_ips),
    .json_name = "interface_ip",
    .cb_function = _cb_create_text_interface_ip,
  },
  {
    .data = _td_neigh,
    .data_size = ARRAYSIZE(_td_neigh),
    .json_name = "neighbor",
    .cb_function = _cb_create_text_neighbor,
  },
  {
    .data = _td_neigh_ips,
    .data_size = ARRAYSIZE(_td_neigh_ips),
    .json_name = "neighbor_ip",
    .cb_function = _cb_create_text_neighbor_ip,
  },
  {
    .data = _td_default,
    .data_size = ARRAYSIZE(_td_default),
    .json_name = "default",
    .cb_function = _cb_create_text_default,
  },
  {
    .data = _td_dst,
    .data_size = ARRAYSIZE(_td_dst),
    .json_name = "destination",
    .cb_function = _cb_create_text_dst,
  },
  {
    .data = _td_origin,
    .data_size = ARRAYSIZE(_td_origin),
    .json_name = "origin",
    .cb_function = _cb_create_text_origin,
  },
};

/* telnet command of this plugin */
static struct oonf_telnet_command _telnet_commands[] = {
  TELNET_CMD(OONF_LAYER2INFO_SUBSYSTEM, _cb_layer2info, "", .help_handler = _cb_layer2info_help),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
  OONF_VIEWER_SUBSYSTEM,
};

static struct oonf_subsystem _olsrv2_layer2info_subsystem = {
  .name = OONF_LAYER2INFO_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 layer2 info plugin",
  .author = "Henning Rogge",
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_olsrv2_layer2info_subsystem);

/**
 * Initialize plugin
 * @return -1 if an error happened, 0 otherwise
 */
static int
_init(void) {
  size_t i;

  abuf_init(&_key_storage);

  for (i = 0; i < OONF_LAYER2_NET_COUNT; i++) {
    _tde_if_data[i].key = abuf_getptr(&_key_storage) + abuf_getlen(&_key_storage);
    _tde_if_data[i].value = _value_if_data[i];
    _tde_if_data[i].string = true;

    abuf_puts(&_key_storage, KEY_IF_PREFIX);
    abuf_puts(&_key_storage, oonf_layer2_net_metadata_get(i)->key);
    abuf_memcpy(&_key_storage, "\0", 1);

    _tde_if_origin[i].key = abuf_getptr(&_key_storage) + abuf_getlen(&_key_storage);
    _tde_if_origin[i].value = _value_if_origin[i];
    _tde_if_origin[i].string = true;

    abuf_puts(&_key_storage, KEY_IF_PREFIX);
    abuf_puts(&_key_storage, oonf_layer2_net_metadata_get(i)->key);
    abuf_puts(&_key_storage, KEY_ORIGIN_SUFFIX);
    abuf_memcpy(&_key_storage, "\0", 1);
  }

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    _tde_neigh_data[i].key = abuf_getptr(&_key_storage) + abuf_getlen(&_key_storage);
    _tde_neigh_data[i].value = _value_neigh_data[i];
    _tde_neigh_data[i].string = true;

    abuf_puts(&_key_storage, KEY_NEIGH_PREFIX);
    abuf_puts(&_key_storage, oonf_layer2_neigh_metadata_get(i)->key);
    abuf_memcpy(&_key_storage, "\0", 1);

    _tde_neigh_origin[i].key = abuf_getptr(&_key_storage) + abuf_getlen(&_key_storage);
    _tde_neigh_origin[i].value = _value_neigh_origin[i];
    _tde_neigh_origin[i].string = true;

    abuf_puts(&_key_storage, KEY_NEIGH_PREFIX);
    abuf_puts(&_key_storage, oonf_layer2_neigh_metadata_get(i)->key);
    abuf_puts(&_key_storage, KEY_ORIGIN_SUFFIX);
    abuf_memcpy(&_key_storage, "\0", 1);
  }

  oonf_telnet_add(&_telnet_commands[0]);

  return abuf_has_failed(&_key_storage) ? -1 : 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  oonf_telnet_remove(&_telnet_commands[0]);
  abuf_free(&_key_storage);
}

/**
 * Callback for the telnet command of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_layer2info(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_handler(
    con->out, &_template_storage, OONF_LAYER2INFO_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Callback for the help output of this plugin
 * @param con pointer to telnet session data
 * @return telnet result value
 */
static enum oonf_telnet_result
_cb_layer2info_help(struct oonf_telnet_data *con) {
  return oonf_viewer_telnet_help(
    con->out, OONF_LAYER2INFO_SUBSYSTEM, con->parameter, _templates, ARRAYSIZE(_templates));
}

/**
 * Initialize the value buffers for a layer2 interface
 * @param net pointer to layer2 interface
 */
static void
_initialize_if_values(struct oonf_layer2_net *net) {
  struct os_interface *os_if;

  os_if = net->if_listener.data;

  strscpy(_value_if, net->name, sizeof(_value_if));
  snprintf(_value_if_index, sizeof(_value_if_index), "%u", os_if->index);
  strscpy(_value_if_ident, net->if_ident, sizeof(_value_if_ident));
  netaddr_to_string(&_value_if_local_addr, &os_if->mac);
  strscpy(_value_if_type, oonf_layer2_net_get_type_name(net->if_type), IF_NAMESIZE);
  strscpy(_value_if_dlep, json_getbool(net->if_dlep), TEMPLATE_JSON_BOOL_LENGTH);

  if (net->last_seen) {
    oonf_clock_toIntervalString(&_value_if_lastseen, -oonf_clock_get_relative(net->last_seen));
  }
  else {
    _value_if_lastseen.buf[0] = 0;
  }
}

/**
 * Initialize the value buffers for a l2 peer address object
 * @param peer_ip peer address object
 */
static void
_initialize_if_ip_values(struct oonf_layer2_peer_address *peer_ip) {
  netaddr_to_string(&_value_if_peer_ip, &peer_ip->ip);
  strscpy(_value_if_peer_ip_origin, peer_ip->origin->name, sizeof(_value_if_peer_ip_origin));
}

/**
 * Initialize the value buffers for an array of layer2 data objects
 * @param template viewer template
 * @param l2net layer-2 network data
 */
static void
_initialize_if_data_values(struct oonf_viewer_template *template, struct oonf_layer2_net *l2net) {
  size_t i;

  memset(_value_if_data, 0, sizeof(_value_if_data));

  for (i = 0; i < OONF_LAYER2_NET_COUNT; i++) {
    oonf_layer2_net_data_to_string(_value_if_data[i], sizeof(_value_if_data[i]), l2net, i, template->create_raw);
  }
}

/**
 * Initialize the value buffers for an array of layer2 data objects
 * @param template viewer template
 * @param l2net layer-2 network data
 */
static void
_initialize_if_default_data_values(struct oonf_viewer_template *template, struct oonf_layer2_net *l2net) {
  size_t i;

  memset(_value_neigh_data, 0, sizeof(_value_neigh_data));

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    oonf_layer2_net_default_data_to_string(_value_neigh_data[i], sizeof(_value_neigh_data[i]), l2net, i, template->create_raw);
  }
}

/**
 * Initialize the network origin buffers for an array of layer2 data objects
 * @param data array of data objects
 */
static void
_initialize_if_origin_values(struct oonf_layer2_data *data) {
  size_t i;

  memset(_value_if_origin, 0, sizeof(_value_if_origin));

  for (i = 0; i < OONF_LAYER2_NET_COUNT; i++) {
    if (oonf_layer2_data_has_value(&data[i])) {
      strscpy(_value_if_origin[i], oonf_layer2_data_get_origin(&data[i])->name, IF_NAMESIZE);
    }
  }
}

/**
 * Initialize the value buffers for a layer2 neighbor
 * @param neigh layer2 neighbor
 */
static void
_initialize_neigh_values(struct oonf_layer2_neigh *neigh) {
  netaddr_to_string(&_value_neigh_addr, &neigh->key.addr);
  oonf_layer2_neigh_key_to_string(&_value_neigh_key, &neigh->key, false);
  snprintf(_value_neigh_key_length, sizeof(_value_neigh_key_length), "%u", neigh->key.link_id_length);

  netaddr_to_string(&_value_neigh_nexthop_v4, oonf_layer2_neigh_get_nexthop(neigh, AF_INET));
  netaddr_to_string(&_value_neigh_nexthop_v6, oonf_layer2_neigh_get_nexthop(neigh, AF_INET6));

  if (oonf_layer2_neigh_get_lastseen(neigh)) {
    oonf_clock_toIntervalString(&_value_neigh_lastseen, -oonf_clock_get_relative(oonf_layer2_neigh_get_lastseen(neigh)));
  }
  else {
    _value_neigh_lastseen.buf[0] = 0;
  }
}

/**
 * Initialize the value buffers for a l2 neighbor remote address object
 * @param neigh_addr neighbor remote address
 */
static void
_initialize_neigh_ip_values(struct oonf_layer2_neighbor_address *neigh_addr) {
  netaddr_to_string(&_value_neigh_remote_ip, &neigh_addr->ip);
  netaddr_to_string(&_value_neigh_remote_ip_nexthop,
      oonf_layer2_neigh_get_nexthop(neigh_addr->l2neigh, netaddr_get_address_family(&neigh_addr->ip)));
  strscpy(_value_neigh_remote_ip_origin, neigh_addr->origin->name, sizeof(_value_neigh_remote_ip_origin));
}

/**
 * Initialize the value buffers for an array of layer2 data objects
 * @param template viewer template
 * @param l2neigh layer-2 neighbor object
 */
static void
_initialize_neigh_data_values(struct oonf_viewer_template *template, struct oonf_layer2_neigh *l2neigh) {
  size_t i;

  memset(_value_neigh_data, 0, sizeof(_value_neigh_data));

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    oonf_layer2_neigh_data_to_string(
      _value_neigh_data[i], sizeof(_value_neigh_data[i]), l2neigh, i, template->create_raw);
  }
}

/**
 * Initialize the network origin buffers for an array of layer2 data objects
 * @param data array of data objects
 */
static void
_initialize_neigh_origin_values(struct oonf_layer2_data *data) {
  size_t i;

  memset(_value_neigh_origin, 0, sizeof(_value_neigh_origin));

  for (i = 0; i < OONF_LAYER2_NEIGH_COUNT; i++) {
    if (oonf_layer2_data_has_value(&data[i])) {
      strscpy(_value_neigh_origin[i], oonf_layer2_data_get_origin(&data[i])->name, IF_NAMESIZE);
    }
  }
}

/**
 * Initialize the value buffers for a layer2 destination
 * @param l2dst layer2 destination
 */
static void
_initialize_destination_values(struct oonf_layer2_destination *l2dst) {
  netaddr_to_string(&_value_dst_addr, &l2dst->destination);
  strscpy(_value_dst_origin, l2dst->origin->name, IF_NAMESIZE);
}

/**
 * Initialize the value buffers for a layer2 originator
 * @param l2origin layer2 originator
 */
static void
_initialize_origin_values(struct oonf_layer2_origin *l2origin) {
  strscpy(_value_origin_name, l2origin->name, sizeof(_value_origin_name));
  strscpy(_value_origin_proactive, json_getbool(l2origin->proactive), sizeof(_value_origin_proactive));
  snprintf(_value_origin_priority, sizeof(_value_origin_priority), "%d", l2origin->priority);
  strscpy(_value_origin_lid, json_getbool(l2origin->lid), sizeof(_value_origin_lid));
  snprintf(_value_origin_lid_index, sizeof(_value_origin_lid_index), "%u", l2origin->lid_index);
}

/**
 * Callback to generate text/json description of all layer2 interfaces
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_interface(struct oonf_viewer_template *template) {
  struct oonf_layer2_net *net;

  avl_for_each_element(oonf_layer2_get_net_tree(), net, _node) {
    _initialize_if_values(net);
    _initialize_if_data_values(template, net);
    _initialize_if_origin_values(net->data);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Callback to generate text/json description of all layer2 interface ips
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_interface_ip(struct oonf_viewer_template *template) {
  struct oonf_layer2_net *net;
  struct oonf_layer2_peer_address *peer_ip;

  avl_for_each_element(oonf_layer2_get_net_tree(), net, _node) {
    _initialize_if_values(net);

    avl_for_each_element(&net->local_peer_ips, peer_ip, _net_node) {
      _initialize_if_ip_values(peer_ip);

      /* generate template output */
      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}

/**
 * Callback to generate text/json description of all layer2 neighbors
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_neighbor(struct oonf_viewer_template *template) {
  struct oonf_layer2_neigh *neigh;
  struct oonf_layer2_net *net;

  avl_for_each_element(oonf_layer2_get_net_tree(), net, _node) {
    _initialize_if_values(net);

    avl_for_each_element(&net->neighbors, neigh, _node) {
      _initialize_neigh_values(neigh);
      _initialize_neigh_data_values(template, neigh);
      _initialize_neigh_origin_values(neigh->data);

      /* generate template output */
      oonf_viewer_output_print_line(template);
    }
  }
  return 0;
}

/**
 * Callback to generate text/json description of all layer2 neighbor ips
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_neighbor_ip(struct oonf_viewer_template *template) {
  struct oonf_layer2_neighbor_address *remote_ip;
  struct oonf_layer2_neigh *neigh;
  struct oonf_layer2_net *net;

  avl_for_each_element(oonf_layer2_get_net_tree(), net, _node) {
    _initialize_if_values(net);

    avl_for_each_element(&net->neighbors, neigh, _node) {
      _initialize_neigh_values(neigh);

      avl_for_each_element(&neigh->remote_neighbor_ips, remote_ip, _neigh_node) {
        _initialize_neigh_ip_values(remote_ip);

        /* generate template output */
        oonf_viewer_output_print_line(template);
      }
    }
  }
  return 0;
}

/**
 * Callback to generate text/json description of the defaults stored
 * in the layer2 interfaces for their neighbors
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_default(struct oonf_viewer_template *template) {
  struct oonf_layer2_net *net;

  avl_for_each_element(oonf_layer2_get_net_tree(), net, _node) {
    _initialize_if_values(net);
    _initialize_if_default_data_values(template, net);
    _initialize_neigh_origin_values(net->neighdata);

    /* generate template output */
    oonf_viewer_output_print_line(template);
  }
  return 0;
}

/**
 * Callback to generate text/json description of all layer2 destinations
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_dst(struct oonf_viewer_template *template) {
  struct oonf_layer2_destination *l2dst;
  struct oonf_layer2_neigh *neigh;
  struct oonf_layer2_net *net;

  avl_for_each_element(oonf_layer2_get_net_tree(), net, _node) {
    _initialize_if_values(net);

    avl_for_each_element(&net->neighbors, neigh, _node) {
      _initialize_neigh_values(neigh);

      avl_for_each_element(&neigh->destinations, l2dst, _node) {
        _initialize_destination_values(l2dst);

        /* generate template output */
        oonf_viewer_output_print_line(template);
      }
    }
  }
  return 0;
}

/**
 * Callback to generate text/json description of all layer2 destinations
 * @param template viewer template
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_create_text_origin(struct oonf_viewer_template *template) {
  struct oonf_layer2_origin *l2origin;

  avl_for_each_element(oonf_layer2_get_origin_tree(), l2origin, _node) {
    _initialize_origin_values(l2origin);
    oonf_viewer_output_print_line(template);
  }
  return 0;
}
