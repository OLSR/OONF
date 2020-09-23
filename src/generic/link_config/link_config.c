
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
#include <oonf/oonf.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libconfig/cfg_validate.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>

#include <oonf/generic/link_config/link_config.h>

/* definitions and constants */
#define LOG_LINK_CONFIG _oonf_link_config_subsystem.logging

/* Prototypes */
static void _early_cfg_init(void);
static int _init(void);
static void _cleanup(void);

static void _cb_update_link_config(void *);
static void _cb_delayed_config(struct oonf_timer_instance *);

static int _cb_validate_linkdata(
  const struct cfg_schema_entry *entry, const char *section_name, const char *value, struct autobuf *out);
static void _parse_strarray(struct strarray *array, const char *ifname, enum oonf_layer2_neighbor_index idx);
static void _cb_config_changed(void);

/* define configuration entries */

/*! configuration validator for linkdata */
#define CFG_VALIDATE_LINKDATA(link_index, p_help, args...)                                                             \
  _CFG_VALIDATE("", "", p_help, .cb_validate = _cb_validate_linkdata, .validate_param = { { .i32 = { link_index } } }, \
    .list = true, ##args)

static struct cfg_schema_entry _link_config_if_entries[] = {
  CFG_VALIDATE_LINKDATA(OONF_LAYER2_NEIGH_RX_BITRATE,
    "Sets the incoming link speed on the interface. Consists of a speed in"
    " bits/s (with iso-prefix) and an optional list of mac addresses of neighbor nodes."),
  CFG_VALIDATE_LINKDATA(OONF_LAYER2_NEIGH_TX_BITRATE,
    "Sets the outgoing link speed on the interface. Consists of a speed in"
    " bits/s (with iso-prefix) and an optional list of mac addresses of neighbor nodes."),
  CFG_VALIDATE_LINKDATA(OONF_LAYER2_NEIGH_RX_MAX_BITRATE,
    "Sets the maximal incoming link speed on the interface. Consists of a speed in"
    " bits/s (with iso-prefix) and an optional list of mac addresses of neighbor nodes."),
  CFG_VALIDATE_LINKDATA(OONF_LAYER2_NEIGH_TX_MAX_BITRATE,
    "Sets the maximal outgoing link speed on the interface. Consists of a speed in"
    " bits/s (with iso-prefix) and an optional list of mac addresses of neighbor nodes."),
  CFG_VALIDATE_LINKDATA(OONF_LAYER2_NEIGH_RX_SIGNAL,
    "Sets the incoing signal strength on the interface. Consists of a signal strength in"
    " dBm (with iso-prefix) and an optional list of mac addresses of neighbor nodes."),
};

static struct cfg_schema_section _link_config_section = {
  CFG_OSIF_SCHEMA_INTERFACE_SECTION_INIT,

  .cb_delta_handler = _cb_config_changed,
  .entries = _link_config_if_entries,
  .entry_count = ARRAYSIZE(_link_config_if_entries),
};

/* declare subsystem */
static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
};
static struct oonf_subsystem _oonf_link_config_subsystem = {
  .name = OONF_LINK_CONFIG_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .early_cfg_init = _early_cfg_init,
  .init = _init,
  .cleanup = _cleanup,

  .cfg_section = &_link_config_section,
};
DECLARE_OONF_PLUGIN(_oonf_link_config_subsystem);

/* originator for smooth set/remove of configured layer2 values */
static struct oonf_layer2_origin _l2_origin_current = {
  .name = "link config updated",
  .priority = OONF_LAYER2_ORIGIN_CONFIGURED,
};
static struct oonf_layer2_origin _l2_origin_old = {
  .name = "link config",
  .priority = OONF_LAYER2_ORIGIN_CONFIGURED,
};

/* listener for removal of layer2 data */
static struct oonf_class_extension _l2net_listener = {
  .ext_name = "link config listener",
  .class_name = LAYER2_CLASS_NETWORK,

  .cb_remove = _cb_update_link_config,
  .cb_change = _cb_update_link_config,
};
static struct oonf_class_extension _l2neigh_listener = {
  .ext_name = "link config listener",
  .class_name = LAYER2_CLASS_NEIGHBOR,

  .cb_remove = _cb_update_link_config,
  .cb_change = _cb_update_link_config,
};

/* timer for lazy updates */
static struct oonf_timer_class _lazy_update_class = {
  .name = "lazy link config",
  .callback = _cb_delayed_config,
};

static struct oonf_timer_instance _lazy_update_instance = {
  .class = &_lazy_update_class,
};

static void
_early_cfg_init(void) {
  struct cfg_schema_entry *entry;
  size_t i;

  for (i = 0; i < ARRAYSIZE(_link_config_if_entries); i++) {
    entry = &_link_config_if_entries[i];
    entry->key.entry =
      oonf_layer2_neigh_metadata_get((enum oonf_layer2_neighbor_index)entry->validate_param[0].i32[0])->key;
  }
}

/**
 * Subsystem constructor
 * @return always returns 0
 */
static int
_init(void) {
  oonf_layer2_origin_add(&_l2_origin_current);
  oonf_layer2_origin_add(&_l2_origin_old);

  oonf_class_extension_add(&_l2net_listener);
  oonf_class_extension_add(&_l2neigh_listener);

  oonf_timer_add(&_lazy_update_class);

  return 0;
}

/**
 * Subsystem destructor
 */
static void
_cleanup(void) {
  oonf_timer_stop(&_lazy_update_instance);
  oonf_timer_remove(&_lazy_update_class);

  oonf_class_extension_remove(&_l2net_listener);
  oonf_class_extension_remove(&_l2neigh_listener);

  oonf_layer2_origin_remove(&_l2_origin_current);
  oonf_layer2_origin_remove(&_l2_origin_old);
}

/**
 * Listener for removal of layer2 database entries. Will trigger
 * a delayed reset of this plugins configured data
 * @param ptr unused
 */
static void
_cb_update_link_config(void *ptr __attribute__((unused))) {
  if (!oonf_timer_is_active(&_lazy_update_instance)) {
    OONF_DEBUG(LOG_LINK_CONFIG, "Trigger lazy update");
    oonf_timer_set(&_lazy_update_instance, OONF_LINK_CONFIG_REWRITE_DELAY);
  }
}

/**
 * Callback for delayed update.
 * @param timer unused
 */
static void
_cb_delayed_config(struct oonf_timer_instance *timer __attribute__((unused))) {
  /* re-read the configuration */
  OONF_DEBUG(LOG_LINK_CONFIG, "Update configuration settings");
  _cb_config_changed();
}

/**
 * Configuration subsystem validator for linkdata
 * @param entry configuration schema entry
 * @param section_name name of the configuration section the entry was set
 * @param value text value of the configuration entry
 * @param out output buffer for error messages
 * @return -1 if validation failed, 0 otherwise
 */
static int
_cb_validate_linkdata(
  const struct cfg_schema_entry *entry, const char *section_name, const char *value, struct autobuf *out) {
  enum oonf_layer2_neighbor_index idx;
  struct isonumber_str sbuf;
  struct netaddr_str nbuf;
  const char *ptr;

  idx = entry->validate_param[0].i32[0];

  /* test if first word is a human readable number */
  ptr = str_cpynextword(sbuf.buf, value, sizeof(sbuf));
  if (cfg_validate_int(out, section_name, entry->key.entry, sbuf.buf, INT64_MIN, INT64_MAX, 8,
        oonf_layer2_neigh_metadata_get(idx)->scaling)) {
    return -1;
  }

  while (ptr) {
    int8_t af[] = { AF_MAC48, AF_EUI64 };

    /* test if the rest of the words are mac addresses */
    ptr = str_cpynextword(nbuf.buf, ptr, sizeof(nbuf));

    if (cfg_validate_netaddr(out, section_name, entry->key.entry, nbuf.buf, false, af, ARRAYSIZE(af))) {
      return -1;
    }
  }
  return 0;
}

/**
 * Parse user input and add the corresponding database entries
 * @param array pointer to string array
 * @param ifname interface name
 * @param idx layer2 neighbor index
 */
static void
_parse_strarray(struct strarray *array, const char *ifname, enum oonf_layer2_neighbor_index idx) {
  const struct oonf_layer2_metadata *meta;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_net *l2net;
  struct netaddr_str nbuf;
  struct netaddr linkmac;
  struct isonumber_str hbuf;
  int64_t value;
  char *entry;
  const char *ptr;

  l2net = oonf_layer2_net_add(ifname);
  if (l2net == NULL) {
    return;
  }

  meta = oonf_layer2_neigh_metadata_get(idx);

  strarray_for_each_element(array, entry) {
    ptr = str_cpynextword(hbuf.buf, entry, sizeof(hbuf));
    if (isonumber_to_s64(&value, hbuf.buf, meta->unit, meta->scaling)) {
      continue;
    }

    if (ptr == NULL) {
      /* add network wide data entry */
      if (!oonf_layer2_data_set_int64(&l2net->neighdata[idx], &_l2_origin_current, meta, value, meta->scaling)) {
        OONF_INFO(LOG_LINK_CONFIG, "if-wide %s for %s: %s", meta->key, ifname, hbuf.buf);
      }
      continue;
    }

    while (ptr) {
      ptr = str_cpynextword(nbuf.buf, ptr, sizeof(nbuf));

      if (netaddr_from_string(&linkmac, nbuf.buf) != 0) {
        break;
      }

      l2neigh = oonf_layer2_neigh_add(l2net, &linkmac);
      if (!l2neigh) {
        continue;
      }

      if (!oonf_layer2_data_set_int64(&l2neigh->data[idx], &_l2_origin_current, meta, value, meta->scaling)) {
        OONF_INFO(LOG_LINK_CONFIG, "%s to neighbor %s on %s: %s", meta->key, nbuf.buf,
          ifname, hbuf.buf);
      }
    }
  }
}

/**
 * Parse configuration change
 */
static void
_cb_config_changed(void) {
  struct cfg_schema_entry *schema_entry;
  enum oonf_layer2_neighbor_index l2idx;
  struct oonf_layer2_neigh *l2neigh, *l2neigh_it;
  struct oonf_layer2_net *l2net;
  struct cfg_entry *entry;
  char ifbuf[IF_NAMESIZE];
  const char *ifname;
  size_t idx;
  bool commit;

  if (_link_config_section.post) {
    for (idx = 0; idx < ARRAYSIZE(_link_config_if_entries); idx++) {
      schema_entry = &_link_config_if_entries[idx];
      l2idx = schema_entry->validate_param[0].i32[0];

      entry = cfg_db_get_entry(_link_config_section.post, schema_entry->key.entry);
      if (entry) {
        _parse_strarray(&entry->val, _link_config_section.section_name, l2idx);
      }
    }
  }

  ifname = cfg_get_phy_if(ifbuf, _link_config_section.section_name);
  l2net = oonf_layer2_net_get(ifname);
  if (l2net) {
    /* remove old entries and trigger remove events */
    oonf_layer2_net_cleanup(l2net, &_l2_origin_old, true);

    commit = false;
    /* detect changes and relabel the origin */
    avl_for_each_element_safe(&l2net->neighbors, l2neigh, _node, l2neigh_it) {
      for (idx = 0; idx < OONF_LAYER2_NEIGH_COUNT; idx++) {
        if (oonf_layer2_data_get_origin(&l2neigh->data[idx]) == &_l2_origin_current) {
          oonf_layer2_data_set_origin(&l2neigh->data[idx], &_l2_origin_old);
          commit = true;
        }
      }
      if (commit) {
        /* trigger change event */
        oonf_layer2_neigh_commit(l2neigh);
      }
    }

    commit = false;
    /* detect changes and relabel the origin */
    for (idx = 0; idx < OONF_LAYER2_NET_COUNT; idx++) {
      if (oonf_layer2_data_get_origin(&l2net->neighdata[idx]) == &_l2_origin_current) {
        oonf_layer2_data_set_origin(&l2net->neighdata[idx], &_l2_origin_old);
        commit = true;
      }
    }
    if (commit) {
      /* trigger change event */
      oonf_layer2_net_commit(l2net);
    }
  }
}
