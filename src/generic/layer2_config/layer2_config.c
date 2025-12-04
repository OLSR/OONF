
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

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/libcommon/string.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libconfig/cfg_tobin.h>
#include <oonf/libconfig/cfg_validate.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_telnet.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/layer2_config/layer2_config.h>

/* definitions and constants */
#define LOG_LAYER2_CONFIG _oonf_layer2_config_subsystem.logging

enum
{
  _MAX_L2_VALUE_LEN = 64
};

enum l2_data_type
{
  L2_NET,
  L2_NET_IP,
  L2_DEF,
  L2_NEIGH,
  L2_NEIGH_IP,
  L2_DST,

  L2_TYPE_COUNT,
};

/* one layer2 configuration option for an interface */
struct l2_config_data {
  enum l2_data_type config_type;
  struct oonf_layer2_neigh_key key;

  int data_idx;

  enum oonf_layer2_data_type data_type;
  union oonf_layer2_value data;
  char txt_value[_MAX_L2_VALUE_LEN];
  bool overwrite;
};

/* all configuration options for an interface */
struct l2_config_if_data {
  char interf[IF_NAMESIZE];

  struct oonf_timer_instance _reconfigure_timer;
  struct avl_node _node;

  size_t count;
  struct l2_config_data d[0];
};

/* Prototypes */
static int _init(void);
static void _cleanup(void);

static struct l2_config_if_data *_add_if_data(const char *ifname, size_t data_count);
static void _remove_if_data(struct l2_config_if_data *);

static int _cb_if_value_validator(struct autobuf *out, const char *section_name, const char *entry_name,
  const char *value, struct cfg_schema_entry *entries, size_t entry_count);
static int _cb_if_value_tobin(struct cfg_schema_entry *entries, size_t entry_count, const char *value, void *ptr);
static int _cb_neigh_value_validator(struct autobuf *out, const char *section_name, const char *entry_name,
  const char *value, struct cfg_schema_entry *entries, size_t entry_count);
static int _cb_neigh_value_tobin(struct cfg_schema_entry *entries, size_t entry_count, const char *value, void *ptr);

static enum oonf_telnet_result _cb_telnet_cmd(struct oonf_telnet_data *con);
static enum oonf_telnet_result _cb_telnet_help(struct oonf_telnet_data *con);

static void _set_if_data(struct oonf_layer2_net *l2net, struct l2_config_data *entry, struct oonf_layer2_origin *origin);
static void _reset_if_data(struct oonf_layer2_net *l2net, struct l2_config_data *entry, struct oonf_layer2_origin *origin);

static void _cb_update_l2net(void *);
static void _cb_update_l2neigh(void *);
static void _cb_reconfigure(struct oonf_timer_instance *);

static void _configure_if_data(const char *ifname, struct l2_config_data *data, size_t data_count);
static void _cb_config_changed(void);

/* define configuration entries */

/*! configuration for linkdata */
static struct cfg_schema_entry _l2net_entries[] = {
  CFG_MAP_CHOICE_L2NET_DATA_KEY(l2_config_data, data_idx, "l2net_key", "", "Layer2 network key for configuration"),
  CFG_MAP_STRING_ARRAY(l2_config_data, txt_value, "l2net_value", "", "Layer2 network value", _MAX_L2_VALUE_LEN),
  CFG_MAP_BOOL(l2_config_data, overwrite, "l2net_overwrite", "false", "Layer2 overwrite priority"),
};
static struct cfg_schema_entry _l2net_ip_entries[] = {
  CFG_MAP_NETADDR_V46(l2_config_data, data.addr,
    "l2net_ip", "", "Sets an ip address/prefix for the local radio in the database", true, false),
  CFG_MAP_BOOL(l2_config_data, overwrite, "l2net_overwrite", "false", "Layer2 overwrite priority"),
};
static struct cfg_schema_entry _l2net_def_entries[] = {
  CFG_MAP_CHOICE_L2NEIGH_DATA_KEY(l2_config_data, data_idx, "l2neigh_key", "", "Layer2 neighbor key for configuration"),
  CFG_MAP_STRING_ARRAY(
    l2_config_data, txt_value, "l2neigh_value", "", "Layer2 neighbor value for default neighbor data", _MAX_L2_VALUE_LEN),
  CFG_MAP_BOOL(l2_config_data, overwrite, "l2net_overwrite", "false", "Layer2 overwrite priority"),
};
static struct cfg_schema_entry _l2neigh_entries[] = {
  CFG_MAP_CHOICE_L2NEIGH_DATA_KEY(l2_config_data, data_idx, "l2neigh_key", "", "Layer2 neighbor key for configuration"),
  CFG_MAP_STRING_ARRAY(l2_config_data, txt_value, "l2neigh_value", "", "Layer2 neighbor value", _MAX_L2_VALUE_LEN),
  CFG_MAP_LAYER2_NEIGH_MAC_LID (l2_config_data, key, "l2neigh_mac", "", "MAC address of neighbor including LID"),
  CFG_MAP_BOOL(l2_config_data, overwrite, "l2net_overwrite", "false", "Layer2 overwrite priority"),
};
static struct cfg_schema_entry _l2neigh_ip_entries[] = {
  CFG_MAP_LAYER2_NEIGH_MAC_LID (l2_config_data, key, "l2neigh_mac", "", "MAC address of neighbor including LID"),
  CFG_MAP_NETADDR_V46(l2_config_data, data.addr, "l2neigh_ip", "", "IP address to neighbor", false, false),
  CFG_MAP_BOOL(l2_config_data, overwrite, "l2neigh_overwrite", "false", "Layer2 overwrite priority"),
};
static struct cfg_schema_entry _l2neigh_dst_entries[] = {
  CFG_MAP_LAYER2_NEIGH_MAC_LID (l2_config_data, key, "l2neigh_mac", "", "MAC address of neighbor including LID"),
  CFG_MAP_NETADDR_MAC48(
    l2_config_data, data.addr, "l2neigh_dst", "", "Secondary MAC address of neighbor", false, false),
  CFG_MAP_BOOL(l2_config_data, overwrite, "l2net_overwrite", "false", "Layer2 overwrite priority"),
};

static struct cfg_schema_token_customizer _overwrite_customizer = {
  .optional = 1,
};

static struct cfg_schema_token_customizer _if_value_customizer = {
  .cb_validator = _cb_if_value_validator,
  .cb_tobin = _cb_if_value_tobin,
  .optional = 1,
};

static struct cfg_schema_token_customizer _neigh_value_customizer = {
  .cb_validator = _cb_neigh_value_validator,
  .cb_tobin = _cb_neigh_value_tobin,
  .optional = 1,
};

static struct cfg_schema_entry _l2_config_if_entries[] = {
  [L2_NET] = CFG_VALIDATE_TOKENS_CUSTOM("l2net", "",
    "Sets an interface wide layer2 entry into the database."
    " Parameters are the key of the interface data followed by the data.",
    _l2net_entries, _if_value_customizer, .list = true),
  [L2_NET_IP] = CFG_VALIDATE_TOKENS_CUSTOM("l2net_ip", "",
    "Sets a network specific ip address/prefix into the database."
    " Parameters is th the ip address/prefix.",
    _l2net_ip_entries, _overwrite_customizer, .list = true),
  [L2_DEF] = CFG_VALIDATE_TOKENS_CUSTOM("l2default", "",
    "Sets an interface wide default neighbor layer2 entry into the database."
    " Parameters are the key of the neighbor data followed by the data.",
    _l2net_def_entries, _neigh_value_customizer, .list = true),
  [L2_NEIGH] = CFG_VALIDATE_TOKENS_CUSTOM("l2neighbor", "",
    "Sets an neighbor specific layer2 entry into the database."
    " Parameters are the key of the neighbor data followed by the data and the mac address of the neighbor.",
    _l2neigh_entries, _neigh_value_customizer, .list = true),
  [L2_NEIGH_IP] = CFG_VALIDATE_TOKENS_CUSTOM("l2neighbor_ip", "",
    "Sets an neighbor specific ip address/prefix into the database."
    " Parameters are the mac address and then the ip address/prefix.",
    _l2neigh_ip_entries, _overwrite_customizer, .list = true),
  [L2_DST] = CFG_VALIDATE_TOKENS_CUSTOM("l2destination", "",
    "Sets an neighbor specific bridged MAC destination into the database."
    " Parameters are the mac address of the neighbor and then the proxied mac address.",
    _l2neigh_dst_entries, _overwrite_customizer, .list = true),
};

static struct cfg_schema_section _l2_config_section = {
  CFG_OSIF_SCHEMA_INTERFACE_SECTION_INIT,

  .cb_delta_handler = _cb_config_changed,
  .entries = _l2_config_if_entries,
  .entry_count = ARRAYSIZE(_l2_config_if_entries),
};

/* declare subsystem */
static const char *_dependencies[] = {
  OONF_LAYER2_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
};
static struct oonf_subsystem _oonf_layer2_config_subsystem = {
  .name = OONF_LAYER2_CONFIG_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,

  .cfg_section = &_l2_config_section,
};
DECLARE_OONF_PLUGIN(_oonf_layer2_config_subsystem);

/* originator for smooth set/remove of configured layer2 values */
static struct oonf_layer2_origin _l2_origin_current_configured = {
  .name = "l2config",
  .priority = OONF_LAYER2_ORIGIN_CONFIGURED,
};
static struct oonf_layer2_origin _l2_origin_current_overwrite = {
  .name = "l2config overwrite",
  .priority = OONF_LAYER2_ORIGIN_OVERWRITE,
};
static struct oonf_layer2_origin _l2_origin_old = {
  .name = "l2config old",
  .priority = OONF_LAYER2_ORIGIN_UNKNOWN,
};

/* listener for removal of layer2 data */
static struct oonf_class_extension _l2net_listener = {
  .ext_name = "link config listener",
  .class_name = LAYER2_CLASS_NETWORK,

  .cb_remove = _cb_update_l2net,
  .cb_change = _cb_update_l2net,
};
static struct oonf_class_extension _l2neigh_listener = {
  .ext_name = "link config listener",
  .class_name = LAYER2_CLASS_NEIGHBOR,

  .cb_remove = _cb_update_l2neigh,
  .cb_change = _cb_update_l2neigh,
};

/* interface data */
static struct avl_tree _if_data_tree;

/* interface reconfiguration timer */
static struct oonf_timer_class _reconfigure_timer = {
  .name = "layer2 reconfiguration",
  .callback = _cb_reconfigure,
};

/* telnet command */
static struct oonf_telnet_command _telnet_l2config[] = {
  TELNET_CMD("l2config", _cb_telnet_cmd, "", .help_handler = _cb_telnet_help),
};

/**
 * Subsystem constructor
 * @return always returns 0
 */
static int
_init(void) {
  oonf_layer2_origin_add(&_l2_origin_current_configured);
  oonf_layer2_origin_add(&_l2_origin_current_overwrite);
  oonf_layer2_origin_add(&_l2_origin_old);

  oonf_class_extension_add(&_l2net_listener);
  oonf_class_extension_add(&_l2neigh_listener);

  oonf_timer_add(&_reconfigure_timer);

  oonf_telnet_add(&_telnet_l2config[0]);
  avl_init(&_if_data_tree, avl_comp_strcasecmp, false);
  return 0;
}

/**
 * Subsystem destructor
 */
static void
_cleanup(void) {
  struct l2_config_if_data *if_data, *if_data_it;

  avl_for_each_element_safe(&_if_data_tree, if_data, _node, if_data_it) {
    _remove_if_data(if_data);
  }
  oonf_telnet_remove(&_telnet_l2config[0]);
  oonf_timer_remove(&_reconfigure_timer);

  oonf_class_extension_remove(&_l2net_listener);
  oonf_class_extension_remove(&_l2neigh_listener);

  oonf_layer2_origin_remove(&_l2_origin_current_overwrite);
  oonf_layer2_origin_remove(&_l2_origin_current_configured);
  oonf_layer2_origin_remove(&_l2_origin_old);
}

/**
 * Add a new layer2 config interface data
 * @param ifname name of interface
 * @param data_count number of data entries
 * @return interface entry, NULL if out of memory
 */
static struct l2_config_if_data *
_add_if_data(const char *ifname, size_t data_count) {
  struct l2_config_if_data *if_data;

  if_data = avl_find_element(&_if_data_tree, ifname, if_data, _node);
  if (if_data) {
    _remove_if_data(if_data);
  }

  if_data = calloc(1, sizeof(struct l2_config_if_data) + data_count * sizeof(struct l2_config_data));
  if (!if_data) {
    OONF_WARN(LOG_LAYER2_CONFIG, "Out of memory for %" PRINTF_SIZE_T_SPECIFIER " ifdata entries for interface %s",
      data_count, _l2_config_section.section_name);
    return NULL;
  }

  /* hook into tree */
  strscpy(if_data->interf, ifname, IF_NAMESIZE);
  if_data->_node.key = if_data->interf;

  avl_insert(&_if_data_tree, &if_data->_node);

  /* initialize timer */
  if_data->_reconfigure_timer.class = &_reconfigure_timer;

  return if_data;
}

/**
 * removes a layer2 config interface data
 * @param if_data interface data
 */
static void
_remove_if_data(struct l2_config_if_data *if_data) {
  if (!avl_is_node_added(&if_data->_node)) {
    return;
  }

  oonf_timer_stop(&if_data->_reconfigure_timer);
  avl_remove(&_if_data_tree, &if_data->_node);
  free(if_data);
}

/**
 * Validate interface setting for layer2 data
 * @param out buffer for validation errors
 * @param section_name name of configuration section
 * @param entry_name name of configuration entries
 * @param value value to be validated
 * @param entries subentries of token config options
 * @param entry_count number of subentries
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_if_value_validator(struct autobuf *out, const char *section_name, const char *entry_name, const char *value,
  struct cfg_schema_entry *entries, size_t entry_count) {
  struct l2_config_data l2_data;
  const struct oonf_layer2_metadata *meta;
  union oonf_layer2_value dst;
  int error;

  if (cfg_tobin_tokens(&l2_data, value, entries, entry_count, NULL)) {
    return -1;
  }

  meta = oonf_layer2_net_metadata_get(l2_data.data_idx);

  if ((error = oonf_layer2_data_parse_string(&dst, meta, l2_data.txt_value))) {
    cfg_append_printable_line(out,
        "Value '%s' for entry '%s' in section %s does not use the data"
        " type '%s' for layer2 network key %s (%d)",
        l2_data.txt_value, entry_name, section_name, oonf_layer2_data_get_type_string(meta),
        meta->key, error);
    return -1;
  }
  return 0;
}

/**
 * Finalize binary conversion of layer2 interface config entry
 * @param entries configuration subentries
 * @param entry_count number of subentries
 * @param value (non-tokenized) value of tokens
 * @param ptr pointer to binary destination
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_if_value_tobin(struct cfg_schema_entry *entries __attribute__((unused)), size_t entry_count __attribute__((unused)),
  const char *value __attribute__((unused)), void *ptr) {
  struct l2_config_data *l2_data;
  const struct oonf_layer2_metadata *meta;

  l2_data = ptr;

  meta = oonf_layer2_net_metadata_get(l2_data->data_idx);
  if (oonf_layer2_data_parse_string(&l2_data->data, meta, l2_data->txt_value)) {
    return -1;
  }
  l2_data->data_type = meta->type;
  return 0;
}

/**
 * Validate neighbor setting for layer2 data
 * @param out buffer for validation errors
 * @param section_name name of configuration section
 * @param entry_name name of configuration entries
 * @param value value to be validated
 * @param entries subentries of token config options
 * @param entry_count number of subentries
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_neigh_value_validator(struct autobuf *out, const char *section_name, const char *entry_name, const char *value,
  struct cfg_schema_entry *entries, size_t entry_count) {
  struct l2_config_data l2_data;
  const struct oonf_layer2_metadata *meta;
  union oonf_layer2_value dst;
  int error;

  if (cfg_tobin_tokens(&l2_data, value, entries, entry_count, NULL)) {
    return -1;
  }

  meta = oonf_layer2_neigh_metadata_get(l2_data.data_idx);

  if ((error = oonf_layer2_data_parse_string(&dst, meta, l2_data.txt_value))) {
    cfg_append_printable_line(out,
        "Value '%s' for entry '%s' in section %s does not use the data"
        " type '%s' for layer2 neighbor key %s (%d)",
        l2_data.txt_value, entry_name, section_name, oonf_layer2_data_get_type_string(meta),
        meta->key, error);
    return -1;
  }
  return 0;
}

/**
 * Finalize binary conversion of layer2 network config entry
 * @param entries configuration subentries
 * @param entry_count number of subentries
 * @param value (non-tokenized) value of tokens
 * @param ptr pointer to binary destination
 * @return -1 if an error happened, 0 otherwise
 */
static int
_cb_neigh_value_tobin(struct cfg_schema_entry *entries __attribute__((unused)),
  size_t entry_count __attribute__((unused)), const char *value __attribute__((unused)), void *ptr) {
  struct l2_config_data *l2_data;
  const struct oonf_layer2_metadata *meta;

  l2_data = ptr;

  meta = oonf_layer2_neigh_metadata_get(l2_data->data_idx);
  if (oonf_layer2_data_parse_string(&l2_data->data, meta, l2_data->txt_value)) {
    return -1;
  }
  l2_data->data_type = meta->type;
  return 0;
}

static enum oonf_telnet_result
_cb_telnet_cmd(struct oonf_telnet_data *con) {
  struct oonf_layer2_origin *origin;
  struct oonf_layer2_net *l2net;
  struct l2_config_data data;
  const char *param, *next;
  char ifname[IF_NAMESIZE];
  struct const_strarray strvalue;
  bool add;

#if 0
             "l2config add/remove l2net <if> <l2net_key> <l2net_value> <l2net_overwrite>\n"
             "l2config add/remove l2net_ip <if> <ip>\n"
             "l2config add/remove l2default <if> <l2neigh_key> <l2neigh_value> <l2net_overwrite>\n"
             "l2config add/remove l2neighbor <if> <l2neigh_key> <l2neigh_value> <l2neigh_mac> <l2net_overwrite>\n"
             "l2config add/remove l2neighbor_ip <if> <l2neigh_key> <l2neigh_ip> <l2net_overwrite>\n"
             "l2config add/remove l2destination <if> <l2neigh_key> <l2neigh_dst> <l2net_overwrite>\n"
#endif

  if (!con->parameter || !con->parameter[0]) {
    abuf_puts(con->out, "Missing parameters for telnet command\n");
    return TELNET_RESULT_ACTIVE;
  }

  memset(&data, 0, sizeof(data));

  param = con->parameter;
  if ((next = str_hasnextword(param, "add"))) {
    add = true;
  }
  else if ((next = str_hasnextword(param, "remove"))) {
    add = false;
  }
  else {
    abuf_puts(con->out, "First parameter must be 'add' or 'remove'");
    return TELNET_RESULT_ACTIVE;
  }

  param = next;
  if ((next = str_hasnextword(param, "l2net"))) {
    data.config_type = L2_NET;
  }
  else if ((next = str_hasnextword(param, "l2net_ip"))) {
    data.config_type = L2_NET_IP;
  }
  else if ((next = str_hasnextword(param, "l2default"))) {
    data.config_type = L2_DEF;
  }
  else if ((next = str_hasnextword(param, "l2neighbor"))) {
    data.config_type = L2_NEIGH;
  }
  else if ((next = str_hasnextword(param, "l2neighbor_ip"))) {
    data.config_type = L2_NEIGH_IP;
  }
  else if ((next = str_hasnextword(param, "l2destination"))) {
    data.config_type = L2_DST;
  }
  else {
    abuf_puts(con->out, "Second parameter must be 'l2net', 'l2net_ip', 'l2default', 'l2neighbor', 'l2neighbor_ip' or 'l2destination'");
    return TELNET_RESULT_ACTIVE;
  }

  param = next;
  if (!(next = str_cpynextword(ifname, param, IF_NAMESIZE))) {
    abuf_puts(con->out, "Missing interface parameter");
    return TELNET_RESULT_ACTIVE;
  }
  abuf_puts(con->out, "1\n");

  if (cfg_schema_validate_tokens(&_l2_config_if_entries[data.config_type], "telnet", next, con->out)) {
    return TELNET_RESULT_ACTIVE;
  }

  abuf_appendf(con->out, "2: '%s'\n", next);
  strvalue.length = strlen(next);
  strvalue.value = next;
  if (cfg_schema_tobin_tokens(&_l2_config_if_entries[data.config_type], &strvalue, &data)) {
    abuf_puts(con->out, "Could not convert input data to binary\n");
    return TELNET_RESULT_ACTIVE;
  }
  abuf_puts(con->out, "3\n");

  origin = data.overwrite ? &_l2_origin_current_overwrite : &_l2_origin_current_configured;
  if (add) {
    l2net = oonf_layer2_net_add(ifname);
    if (!l2net) {
      abuf_puts(con->out, "Could not generate layer2 interface entry");
      return TELNET_RESULT_ACTIVE;
    }
    _set_if_data(l2net, &data, origin);
  }
  else {
    l2net = oonf_layer2_net_get(ifname);
    if (l2net) {
      _reset_if_data(l2net, &data, origin);
    }
  }

  return TELNET_RESULT_ACTIVE;
}


static enum oonf_telnet_result
_cb_telnet_help(struct oonf_telnet_data *con) {
  size_t i;

  if (con->parameter != NULL) {
    for (i=0; i<ARRAYSIZE(_l2_config_if_entries); i++) {
      if (strcmp(_l2_config_if_entries[i].key.entry, con->parameter) == 0) {
        _l2_config_if_entries[i].cb_valhelp(&_l2_config_if_entries[i], con->out);
        return TELNET_RESULT_ACTIVE;
      }
    }
    abuf_appendf(con->out, "Unknown parameter '%s' for command l2config\n", con->parameter);
  }

  abuf_puts(con->out,
             "l2config add/remove l2net <if> <l2net_key> <l2net_value> <l2net_overwrite>\n"
             "l2config add/remove l2net_ip <if> <ip> <l2net_overwrite>\n"
             "l2config add/remove l2default <if> <l2neigh_key> <l2neigh_value> <l2net_overwrite>\n"
             "l2config add/remove l2neighbor <if> l2neigh_key> <l2neigh_value> <l2neigh_mac> <l2net_overwrite>\n"
             "l2config add/remove l2neighbor_ip <if> <l2neigh_mac> <l2neigh_ip> <l2net_overwrite>\n"
             "l2config add/remove l2destination <if> <l2neigh_mac> <l2neigh_dst> <l2net_overwrite>\n"
  );
  return TELNET_RESULT_ACTIVE;
}

/**
 * Callback when a layer2 network entry is changed/removed
 * @param ptr l2net entry
 */
static void
_cb_update_l2net(void *ptr) {
  struct oonf_layer2_net *l2net;
  struct l2_config_if_data *if_data;

  l2net = ptr;

  if_data = avl_find_element(&_if_data_tree, l2net->name, if_data, _node);
  if (if_data && !oonf_timer_is_active(&if_data->_reconfigure_timer)) {
    OONF_DEBUG(LOG_LAYER2_CONFIG, "Received update for l2net: %s", l2net->name);
    oonf_timer_set(&if_data->_reconfigure_timer, LAYER2_RECONFIG_DELAY);
  }
}

/**
 * Callback when a layer2 neighbor entry is changed/removed
 * @param ptr l2net entry
 */
static void
_cb_update_l2neigh(void *ptr) {
  struct oonf_layer2_neigh *l2neigh;
  struct l2_config_if_data *if_data;

  l2neigh = ptr;

  if_data = avl_find_element(&_if_data_tree, l2neigh->network->name, if_data, _node);
  if (if_data && !oonf_timer_is_active(&if_data->_reconfigure_timer)) {
    OONF_DEBUG(LOG_LAYER2_CONFIG, "Received update for l2neigh: %s", l2neigh->network->name);
    oonf_timer_set(&if_data->_reconfigure_timer, LAYER2_RECONFIG_DELAY);
  }
}

/**
 * Timer called for delayed layer2 config update
 * @param timer timer entry
 */
static void
_cb_reconfigure(struct oonf_timer_instance *timer) {
  struct l2_config_if_data *if_data;

  if_data = container_of(timer, typeof(*if_data), _reconfigure_timer);
  _configure_if_data(if_data->interf, if_data->d, if_data->count);
}

static void
_set_if_data(struct oonf_layer2_net *l2net, struct l2_config_data *entry, struct oonf_layer2_origin *origin) {
  struct oonf_layer2_neigh *l2neigh;

  switch (entry->config_type) {
    case L2_NET:
      oonf_layer2_data_set(&l2net->data[entry->data_idx], origin,
                           oonf_layer2_net_metadata_get(entry->data_idx), &entry->data);
      break;
    case L2_NET_IP:
      oonf_layer2_net_add_ip(l2net, origin, &entry->data.addr);
      break;
    case L2_DEF:
      oonf_layer2_data_set(&l2net->neighdata[entry->data_idx], origin,
                           oonf_layer2_neigh_metadata_get(entry->data_idx), &entry->data);
      break;
    case L2_NEIGH:
      l2neigh = oonf_layer2_neigh_add_lid(l2net, &entry->key);
      if (l2neigh) {
        oonf_layer2_data_set(&l2neigh->data[entry->data_idx], origin,
                             oonf_layer2_neigh_metadata_get(entry->data_idx), &entry->data);
      }
      break;
    case L2_NEIGH_IP:
      l2neigh = oonf_layer2_neigh_add_lid(l2net, &entry->key);
      if (l2neigh) {
        oonf_layer2_neigh_add_ip(l2neigh, origin, &entry->data.addr);
      }
      break;
    case L2_DST:
      l2neigh = oonf_layer2_neigh_add_lid(l2net, &entry->key);
      if (l2neigh) {
        oonf_layer2_destination_add(l2neigh, &entry->data.addr, origin);
      }
      break;
    default:
      break;
  }
}

static void
_reset_if_data(struct oonf_layer2_net *l2net, struct l2_config_data *entry, struct oonf_layer2_origin *origin) {
  struct oonf_layer2_neighbor_address *l2_remote_ip;
  struct oonf_layer2_peer_address *l2_local_peer;
  struct oonf_layer2_destination *l2_neigh_dest;
  struct oonf_layer2_neigh *l2neigh;

  switch (entry->config_type) {
    case L2_NET:
      oonf_layer2_data_reset(&l2net->data[entry->data_idx]);

      break;
    case L2_NET_IP:
      l2_local_peer = oonf_layer2_net_get_local_ip(l2net, &entry->data.addr);
      if (l2_local_peer) {
        oonf_layer2_net_remove_ip(l2_local_peer, origin);
      }
      break;
    case L2_DEF:
      oonf_layer2_data_reset(&l2net->neighdata[entry->data_idx]);
      break;
    case L2_NEIGH:
      l2neigh = oonf_layer2_neigh_get_lid(l2net, &entry->key);
      if (l2neigh) {
        oonf_layer2_data_reset(&l2neigh->data[entry->data_idx]);
      }
      break;
    case L2_NEIGH_IP:
      l2neigh = oonf_layer2_neigh_get_lid(l2net, &entry->key);
      if (l2neigh) {
        l2_remote_ip = oonf_layer2_neigh_get_remote_ip(l2neigh, &entry->data.addr);
        if (l2_remote_ip) {
          oonf_layer2_neigh_remove_ip(l2_remote_ip, origin);
        }
      }
      break;
    case L2_DST:
      l2neigh = oonf_layer2_neigh_get_lid(l2net, &entry->key);
      if (l2neigh) {
        l2_neigh_dest = oonf_layer2_destination_get(l2neigh, &entry->data.addr);
        if (l2_neigh_dest) {
          oonf_layer2_destination_remove(l2_neigh_dest);
        }
      }
      break;
    default:
      break;
  }
}

/**
 * Apply a layer2 config interface to the l2 database
 * @param if_data interface data
 */
static void
_configure_if_data(const char *ifname, struct l2_config_data *data, size_t data_count) {
  struct oonf_layer2_net *l2net;
  size_t i;

  l2net = oonf_layer2_net_get(ifname);
  if (!l2net && data_count > 0) {
    l2net = oonf_layer2_net_add(ifname);
    if (!l2net) {
      return;
    }
  }

  /* relabel old entries */
  if (l2net) {
    oonf_layer2_net_relabel(l2net, &_l2_origin_old, &_l2_origin_current_configured);
    oonf_layer2_net_relabel(l2net, &_l2_origin_old, &_l2_origin_current_overwrite);

    for (i = 0; i < data_count; i++) {
      _set_if_data(l2net, &data[i], data[i].overwrite ? &_l2_origin_current_overwrite : &_l2_origin_current_configured);
    }

    /* remove old data */
    oonf_layer2_net_remove(l2net, &_l2_origin_old);
  }
}

/**
 * Parse configuration change
 */
static void
_cb_config_changed(void) {
  struct l2_config_if_data *if_data;
  struct cfg_entry *entry;
  char ifbuf[IF_NAMESIZE];
  const char *txt_value;
  const char *ifname;
  size_t i, total;

  ifname = cfg_get_phy_if(ifbuf, _l2_config_section.section_name);
  if_data = avl_find_element(&_if_data_tree, ifname, if_data, _node);
  if (if_data) {
    _remove_if_data(if_data);
  }

  if (!_l2_config_section.post) {
    /* section was removed */
    return;
  }

  total = 0;
  for (i = 0; i < L2_TYPE_COUNT; i++) {
    entry = cfg_db_get_entry(_l2_config_section.post, _l2_config_if_entries[i].key.entry);
    if (entry) {
      total += strarray_get_count(&entry->val);
    }
  }

  if_data = _add_if_data(_l2_config_section.section_name, total);
  if (!if_data) {
    OONF_WARN(LOG_LAYER2_CONFIG, "Out of memory for %" PRINTF_SIZE_T_SPECIFIER " ifdata entries for interface %s",
      total, _l2_config_section.section_name);
    return;
  }

  /* initialize header */
  strscpy(if_data->interf, _l2_config_section.section_name, IF_NAMESIZE);
  if_data->_node.key = if_data->interf;

  avl_insert(&_if_data_tree, &if_data->_node);

  /* initialize data */
  total = 0;
  for (i = 0; i < L2_TYPE_COUNT; i++) {
    entry = cfg_db_get_entry(_l2_config_section.post, _l2_config_if_entries[i].key.entry);
    if (entry) {
      strarray_for_each_element(&entry->val, txt_value) {
        /*
         * assume that the data type is "address", we will overwrite it for
         * other variants in the next function call.
         */
        if_data->d[total].data_type = OONF_LAYER2_NETWORK_DATA;
        if (!cfg_tobin_tokens(&if_data->d[total], txt_value, _l2_config_if_entries[i].validate_param[0].ptr,
              _l2_config_if_entries[i].validate_param[1].s, _l2_config_if_entries[i].validate_param[2].ptr)) {
          if_data->d[total].config_type = i;
          total++;
        }
      }
    }
  }

  if_data->count = total;

  /* reconfigure layer2 database */
  _configure_if_data(if_data->interf, if_data->d, if_data->count);

  /* stop update timer */
  oonf_timer_stop(&if_data->_reconfigure_timer);
}
