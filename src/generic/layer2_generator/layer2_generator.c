
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
#include <oonf/libcommon/string.h>
#include <oonf/libcommon/template.h>

#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/generic/layer2_generator/layer2_generator.h>

/* Definitions */
#define LOG_L2GEN _layer2_generator_subsystem.logging

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _cb_l2gen_event(struct oonf_timer_instance *);

static void _cb_config_changed(void);

/**
 * Configuration of layer2 generator
 */
struct _l2_generator_config {
  /*! interval between two layer2 event generations */
  uint64_t interval;

  /*! true if generator is active */
  bool active;

  /*! name of interface for event generation */
  char interface[IF_NAMESIZE];

  /*! neighbor mac address for event generation */
  struct netaddr neighbor;

  /*! proxied MAC behind neighbor for event generation */
  struct netaddr destination;
};

static struct oonf_timer_class _l2gen_timer_info = {
  .name = "L2 Generator event",
  .callback = _cb_l2gen_event,
  .periodic = true,
};

static struct oonf_timer_instance _l2gen_timer = {
  .class = &_l2gen_timer_info,
};

/* configuration */
static struct _l2_generator_config _l2gen_config;

static struct cfg_schema_entry _l2gen_entries[] = {
  CFG_MAP_CLOCK_MIN(_l2_generator_config, interval, "interval", "3.000", "Interval between L2 generator events", 500),
  CFG_MAP_STRING_ARRAY(_l2_generator_config, interface, "interface", "eth0", "Interface of example radio", IF_NAMESIZE),
  CFG_MAP_NETADDR_MAC48(
    _l2_generator_config, neighbor, "neighbor", "02:00:00:00:00:01", "Mac address of example radio", false, false),
  CFG_MAP_NETADDR_MAC48(_l2_generator_config, destination, "destination", "02:00:00:00:00:02",
    "Mac address of example radio destination", false, true),
  CFG_MAP_BOOL(_l2_generator_config, active, "active", "false", "Activates artificially generated layer2 data"),
};

static struct cfg_schema_section _l2gen_section = {
  .type = OONF_L2GEN_SUBSYSTEM,
  .cb_delta_handler = _cb_config_changed,
  .entries = _l2gen_entries,
  .entry_count = ARRAYSIZE(_l2gen_entries),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_CLOCK_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
};

static struct oonf_subsystem _layer2_generator_subsystem = {
  .name = OONF_L2GEN_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OONF layer2-generator plugin",
  .author = "Henning Rogge",

  .cfg_section = &_l2gen_section,

  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(_layer2_generator_subsystem);

static struct oonf_layer2_origin _origin = {
  .name = "layer2 generator",
  .proactive = true,
  .priority = OONF_LAYER2_ORIGIN_CONFIGURED,
};

/**
 * Constructor of plugin
 * @return 0 if initialization was successful, -1 otherwise
 */
static int
_init(void) {
  memset(&_l2gen_config, 0, sizeof(_l2gen_config));

  oonf_layer2_origin_add(&_origin);
  oonf_timer_add(&_l2gen_timer_info);
  oonf_timer_start(&_l2gen_timer, 5000);
  return 0;
}

/**
 * Destructor of plugin
 */
static void
_cleanup(void) {
  oonf_layer2_origin_remove(&_origin);
  oonf_timer_stop(&_l2gen_timer);
  oonf_timer_remove(&_l2gen_timer_info);
}

static void
_set_data(struct oonf_layer2_data *data, const struct oonf_layer2_metadata *meta, int64_t value) {
  switch (meta->type) {
    case OONF_LAYER2_INTEGER_DATA:
      oonf_layer2_data_set_int64(data, &_origin, meta, value, meta->scaling);
      break;
    case OONF_LAYER2_BOOLEAN_DATA:
      oonf_layer2_data_set_bool(data, &_origin, meta, (value & 1) != 0);
      break;
    default:
      break;
  }
}

/**
 * Callback for generating new layer2 test data
 * @param ptr timer instance that fired
 */
static void
_cb_l2gen_event(struct oonf_timer_instance *ptr __attribute((unused))) {
  static uint64_t event_counter = 100;
  enum oonf_layer2_network_index net_idx;
  enum oonf_layer2_neighbor_index neigh_idx;
  struct oonf_layer2_net *net;
  struct oonf_layer2_neigh *neigh;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf1;
#endif

  if (!oonf_layer2_origin_is_added(&_origin)) {
    return;
  }

  event_counter++;

  OONF_DEBUG(LOG_L2GEN, "L2Gen-Event triggered (%s/%s/%" PRIu64 ")", _l2gen_config.interface,
    netaddr_to_string(&buf1, &_l2gen_config.neighbor), event_counter);

  net = oonf_layer2_net_add(_l2gen_config.interface);
  if (net == NULL) {
    OONF_WARN(LOG_L2GEN, "Cannot allocate layer2_network");
    return;
  }

  strscpy(net->if_ident, "Interface generated by layer2-generator plugin", sizeof(net->if_ident));
  net->if_type = OONF_LAYER2_TYPE_UNDEFINED;
  net->last_seen = oonf_clock_getNow();

  for (net_idx = 0; net_idx < OONF_LAYER2_NET_COUNT; net_idx++) {
    _set_data(&net->data[net_idx], oonf_layer2_net_metadata_get(net_idx), event_counter);
  }
  for (neigh_idx = 0; neigh_idx < OONF_LAYER2_NEIGH_COUNT; neigh_idx++) {
    _set_data(&net->neighdata[neigh_idx], oonf_layer2_neigh_metadata_get(neigh_idx), event_counter);
  }

  if (oonf_layer2_net_commit(net)) {
    /* something bad has happened, l2net was removed */
    OONF_WARN(LOG_L2GEN, "Could not commit interface %s", _l2gen_config.interface);
    return;
  }

  neigh = oonf_layer2_neigh_add(net, &_l2gen_config.neighbor);
  if (neigh == NULL) {
    OONF_WARN(LOG_L2GEN, "Cannot allocate layer2_neighbor");
    return;
  }

  if (netaddr_get_address_family(&_l2gen_config.destination) == AF_MAC48) {
    oonf_layer2_destination_add(neigh, &_l2gen_config.destination, &_origin);
  }
  memcpy(&neigh->key.addr, &_l2gen_config.neighbor, sizeof(neigh->key.addr));
  neigh->key.link_id[0] = event_counter & 0xff;
  neigh->key.link_id_length = 1;
  oonf_layer2_neigh_set_lastseen(neigh, oonf_clock_getNow());

  for (neigh_idx = 0; neigh_idx < OONF_LAYER2_NEIGH_COUNT; neigh_idx++) {
    _set_data(&neigh->data[neigh_idx], oonf_layer2_neigh_metadata_get(neigh_idx), event_counter);
  }
  oonf_layer2_neigh_commit(neigh);
}

static void
_cb_config_changed(void) {
  if (cfg_schema_tobin(&_l2gen_config, _l2gen_section.post, _l2gen_entries, ARRAYSIZE(_l2gen_entries))) {
    OONF_WARN(LOG_L2GEN, "Could not convert " OONF_L2GEN_SUBSYSTEM " plugin configuration");
    return;
  }

  cfg_get_phy_if(_l2gen_config.interface, _l2gen_config.interface);

  OONF_DEBUG(LOG_L2GEN, "Generator is now %s for interface %s\n", _l2gen_config.active ? "active" : "inactive",
    _l2gen_config.interface);

  if (!oonf_layer2_origin_is_added(&_origin) && _l2gen_config.active) {
    oonf_layer2_origin_add(&_origin);
  }
  else if (oonf_layer2_origin_is_added(&_origin) && !_l2gen_config.active) {
    oonf_layer2_origin_remove(&_origin);
  }

  /* set new interval */
  oonf_timer_set(&_l2gen_timer, _l2gen_config.interval);
}
