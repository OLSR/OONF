
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
#include <oonf/libcommon/autobuf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>

#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/oonf_timer.h>
#include <oonf/base/os_interface.h>
#include <oonf/base/os_routing.h>

#include <oonf/generic/layer2_import/layer2_import.h>

/* definitions */
#define LOG_L2_IMPORT _import_subsystem.logging

/**
 * configuration of one LAN import instance
 */
struct _import_entry {
  /*! name of the lan import */
  char name[20];

  struct oonf_layer2_origin l2origin;

  /*! domain of the lan import */
  int32_t domain;

  /*! address filter */
  struct netaddr_acl filter;

  /*! filter by prefix length */
  int32_t min_prefix_length;

  /*! filter by prefix length */
  int32_t max_prefix_length;

  /*! filter by interface name, length null to ignore*/
  char ifname[IF_NAMESIZE];

  /*! filter by routing table id, -1 to ignore */
  int32_t table;

  /*! filter by routing protocol id, -1 to ignore */
  int32_t protocol;

  /*! block certain routing protocol id, -1 to ignore */
  int32_t block_protocol;

  /*! filter by routing metric, -1 to ignore */
  int32_t distance;

  /*! routing type to be imported, nearly always unicast */
  enum os_route_type rttype;

  /*! true if online routes are put into interface_ip db (and non-onlink are ignored) */
  bool l2net;

  /*! set MAC address of imported entries to this interface */
  char fixed_mac_if[IF_NAMESIZE];

  /*! helper to keep track of MAC of 'fixed' interface */
  struct os_interface_listener fixed_if_listener;

  /*! layer2 interface name for all imported entries, might be empty string */
  char fixed_l2if_name[IF_NAMESIZE];

  /*! tree of all configured lan import */
  struct avl_node _node;
};

/* prototypes */
static int _init(void);
static void _initiate_shutdown(void);
static void _cleanup(void);

static struct _import_entry *_get_import(const char *name);
static void _remove_import(struct _import_entry *);

static void _cb_query(struct os_route *filter, struct os_route *route);
static void _cb_query_finished(struct os_route *, int error);

static void _cb_rt_event(const struct os_route *, bool);
static void _cb_reload_routes(struct oonf_timer_instance *);

static void _cb_lan_cfg_changed(void);
static void _cb_l2_cfg_changed(void);
static void _cb_cfg_changed(struct cfg_schema_section *section, char *section_name);

/* plugin declaration */
static struct cfg_schema_entry _l2_entries[] = {
  CFG_MAP_INT32_MINMAX(
    _import_entry, domain, "domain", "-1", "Routing domain extension for filter, -1 for all domains", 0, -1, 255),
  CFG_MAP_ACL(_import_entry, filter, "matches", ACL_DEFAULT_ACCEPT,
    "Ip addresses the filter should be applied to"
    " (the plugin will never import loopback, linklocal or multicast IPs)"),
  CFG_MAP_INT32_MINMAX(_import_entry, min_prefix_length, "min_prefix_length", "0",
    "Minimal acceptable prefix length to import", 0, 0, 128),
  CFG_MAP_INT32_MINMAX(_import_entry, max_prefix_length, "max_prefix_length", "128",
    "Maximum acceptable prefix length to import", 0, 0, 128),
  CFG_MAP_STRING_ARRAY(
    _import_entry, ifname, "interface", "", "Interface name of matching routes, empty if all interfaces", IF_NAMESIZE),
  CFG_MAP_INT32_MINMAX(
    _import_entry, table, "table", "-1", "Routing table of matching routes, -1 for matching all tables", 0, -1, 65535),
  CFG_MAP_INT32_MINMAX(
    _import_entry, protocol, "protocol", "-1", "Routing protocol of matching routes, -1 for all protocols", 0, -1, 255),
  CFG_MAP_INT32_MINMAX(
    _import_entry, block_protocol, "block_protocol", "-1",
    "Routing protocol not imported, -1 to not block any protocol", 0, -1, 255),
  CFG_MAP_INT32_MINMAX(
    _import_entry, distance, "metric", "-1", "Metric of matching routes, -1 for all metrics", 0, -1, INT32_MAX),
  CFG_MAP_OS_ROUTING_TYPE_KEY(
    _import_entry, rttype, "rttype", "unicast", "Type of routing metric to be imported"),
  CFG_MAP_BOOL(_import_entry, l2net, "l2net", "false", "Put imported onlink routes into interface_ip database"),
  CFG_MAP_STRING_ARRAY(_import_entry, fixed_mac_if, "fixed_mac_if", "",
    "Name of interface that will be used to fill in layer2 entry MAC addresses", IF_NAMESIZE),
  CFG_MAP_STRING_ARRAY(_import_entry, fixed_l2if_name, "fixed_l2if_name", "",
    "Name of interface that will be used to fill in layer2 interface name", IF_NAMESIZE),
};

static struct cfg_schema_entry _lan_entries[] = {
  CFG_MAP_INT32_MINMAX(
    _import_entry, domain, "domain", "-1", "Routing domain extension for filter, -1 for all domains", 0, -1, 255),
  CFG_MAP_ACL(_import_entry, filter, "matches", ACL_DEFAULT_ACCEPT,
    "Ip addresses the filter should be applied to"
    " (the plugin will never import loopback, linklocal or multicast IPs)"),
  CFG_MAP_INT32_MINMAX(_import_entry, min_prefix_length, "min_prefix_length", "0",
    "Minimal acceptable prefix length to import", 0, 0, 128),
  CFG_MAP_INT32_MINMAX(_import_entry, max_prefix_length, "max_prefix_length", "128",
    "Maximum acceptable prefix length to import", 0, 0, 128),
  CFG_MAP_STRING_ARRAY(
    _import_entry, ifname, "interface", "", "Interface name of matching routes, empty if all interfaces", IF_NAMESIZE),
  CFG_MAP_INT32_MINMAX(
    _import_entry, table, "table", "-1", "Routing table of matching routes, -1 for matching all tables", 0, -1, 65535),
  CFG_MAP_INT32_MINMAX(
    _import_entry, protocol, "protocol", "-1", "Routing protocol of matching routes, -1 for all protocols", 0, -1, 255),
  CFG_MAP_INT32_MINMAX(
    _import_entry, block_protocol, "block_protocol", "-1",
    "Routing protocol not imported, -1 to not block any protocol", 0, -1, 255),
  CFG_MAP_INT32_MINMAX(
    _import_entry, distance, "metric", "-1", "Metric of matching routes, -1 for all metrics", 0, -1, INT32_MAX),
  CFG_MAP_OS_ROUTING_TYPE_KEY(
    _import_entry, rttype, "rttype", "unicast", "Type of routing metric to be imported"),
  CFG_MAP_STRING_ARRAY(_import_entry, fixed_mac_if, "fixed_mac_if", "",
    "Name of interface that will be used to fill in layer2 entry MAC addresses", IF_NAMESIZE),
  CFG_MAP_STRING_ARRAY(_import_entry, fixed_l2if_name, "fixed_l2if_name", "",
    "Name of interface that will be used to fill in layer2 interface name", IF_NAMESIZE),
};

static struct cfg_schema_section _lan_import_section = {
  .type = OONF_LAN_IMPORT_SECTION,

  /*
   * this MUST NOT be CFG_SSMODE_NAMED_WITH_DEFAULT, otherwise it will
   * activate without user interaction
   */
  .mode = CFG_SSMODE_NAMED,

  .cb_delta_handler = _cb_lan_cfg_changed,

  .entries = _lan_entries,
  .entry_count = ARRAYSIZE(_lan_entries),
};

static struct cfg_schema_section _l2_import_section = {
  .type = OONF_LAYER2_IMPORT_SUBSYSTEM,

  /*
   * this MUST NOT be CFG_SSMODE_NAMED_WITH_DEFAULT, otherwise it will
   * activate without user interaction
   */
  .mode = CFG_SSMODE_NAMED,

  .cb_delta_handler = _cb_l2_cfg_changed,

  .entries = _l2_entries,
  .entry_count = ARRAYSIZE(_l2_entries),

  .next_section = &_lan_import_section,
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_CLOCK_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OS_INTERFACE_SUBSYSTEM,
  OONF_OS_ROUTING_SUBSYSTEM,
};
static struct oonf_subsystem _import_subsystem = {
  .name = OONF_LAYER2_IMPORT_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 lan-import plugin",
  .author = "Henning Rogge",

  .cfg_section = &_l2_import_section,

  .init = _init,
  .cleanup = _cleanup,
  .initiate_shutdown = _initiate_shutdown,
};
DECLARE_OONF_PLUGIN(_import_subsystem);

/* class definition for filters */
static struct oonf_class _import_class = {
  .name = "l2 import filter",
  .size = sizeof(struct _import_entry),
};

/* timer for triggering 'lazy' reload of routes */
static struct oonf_timer_class _route_reload = {
  .name = "l2 import route reload",
  .callback = _cb_reload_routes,
};
static struct oonf_timer_instance _route_reload_instance = {
  .class = &_route_reload,
};

/* callback filter for dijkstra */
static struct os_route_listener _routing_listener = {
  .cb_get = _cb_rt_event,
};

/* tree of lan importers */
static struct avl_tree _import_tree;

/* wildcard route for first query */
static struct os_route _unicast_query;

/**
 * Initialize plugin
 * @return always returns 0 (cannot fail)
 */
static int
_init(void) {
  avl_init(&_import_tree, avl_comp_strcasecmp, false);

  oonf_class_add(&_import_class);
  oonf_timer_add(&_route_reload);
  os_routing_listener_add(&_routing_listener);

  /* initialize wildcard query */
  os_routing_init_wildcard_route(&_unicast_query);
  _unicast_query.cb_get = _cb_query;
  _unicast_query.cb_finished = _cb_query_finished;
  _unicast_query.p.type = OS_ROUTE_UNDEFINED;
  return 0;
}

static void
_initiate_shutdown(void) {
  /* we are not interested in listening to all the routing cleanup */
  os_routing_listener_remove(&_routing_listener);
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  struct _import_entry *import, *import_it;

  avl_for_each_element_safe(&_import_tree, import, _node, import_it) {
    _remove_import(import);
  }

  oonf_timer_remove(&_route_reload);
  oonf_class_remove(&_import_class);
}

/**
 * Wrapper for cb_get for wildcard query
 * @param filter unused filter
 * @param route route found by wildcard query
 */
static void
_cb_query(struct os_route *filter __attribute__((unused)), struct os_route *route) {
  _cb_rt_event(route, true);
}

/**
 * Dummy cb_finished callback for wildcard query
 * @param route route that was finished
 * @param error error code
 */
static void
_cb_query_finished(struct os_route *route __attribute__((unused)), int error __attribute__((unused))) {}

/**
* Remove old IP entries going to the same destination but different gateway
* and remember (if available) the one with the same gateway
* @param l2net layer2 network to iterate over
* @param import import data
* @param route_gw gateway address
* @param route_dst destination prefix
* @return address to layer2 network address with same gateway and destination, NULL if not found
*/
static struct oonf_layer2_neighbor_address *
_remove_old_entries(struct oonf_layer2_net *l2net, struct _import_entry *import,
                    const struct netaddr *route_gw, const struct netaddr *route_dst) {
  struct oonf_layer2_neighbor_address *match, *l2n_it1, *l2n_start, *l2n_it2;
  const struct netaddr *gw;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  match = NULL;
  OONF_DEBUG(LOG_L2_IMPORT, "route-DST: %s", netaddr_to_string(&nbuf, route_dst));
  l2n_start = avl_find_element(&l2net->remote_neighbor_ips, route_dst, l2n_it1, _net_node);
  l2n_it1 = l2n_start;
  while (l2n_it1 != NULL && (l2n_it1 == l2n_start || l2n_it1->_net_node.follower)) {
    l2n_it2 = avl_next_element_safe(&l2net->remote_neighbor_ips, l2n_it1, _net_node);
      
    OONF_DEBUG(LOG_L2_IMPORT, "l2n-remote: %s", netaddr_to_string(&nbuf, &l2n_it1->ip));
    if (l2n_it1->origin == &import->l2origin) {
      gw = oonf_layer2_neigh_get_nexthop(l2n_it1->l2neigh, netaddr_get_address_family(route_dst));
      if (netaddr_cmp(gw, route_gw) == 0) {
        match = l2n_it1;
      }
      else {
        oonf_layer2_neigh_remove_ip(l2n_it1, &import->l2origin);
      }
    }
    l2n_it1 = l2n_it2;
  }
  return match;
}

/**
 * Callback for route listener
 * @param route routing data
 * @param set true if route was set, false otherwise
 */
static void
_cb_rt_event(const struct os_route *route, bool set) {
  struct _import_entry *import;
  char ifname[IF_NAMESIZE];
  struct oonf_layer2_net *l2net;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_peer_address *l2local;
  struct oonf_layer2_neighbor_address *l2neigh_ip;
  struct oonf_layer2_neigh_key nb_key;
  const struct netaddr *gw, *dst, *mac;
  const char *l2ifname, *macifname;

  struct netaddr_str nbuf;
#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
#endif

  if (netaddr_is_in_subnet(&NETADDR_IPV4_MULTICAST, &route->p.key.dst) ||
      netaddr_is_in_subnet(&NETADDR_IPV4_LINKLOCAL, &route->p.key.dst) ||
      netaddr_is_in_subnet(&NETADDR_IPV4_LOOPBACK_NET, &route->p.key.dst) ||
      netaddr_is_in_subnet(&NETADDR_IPV6_MULTICAST, &route->p.key.dst) ||
      netaddr_is_in_subnet(&NETADDR_IPV6_LINKLOCAL, &route->p.key.dst) ||
      netaddr_is_in_subnet(&NETADDR_IPV6_LOOPBACK, &route->p.key.dst)) {
    /* ignore multicast, linklocal and loopback */
    return;
  }
  OONF_DEBUG(
    LOG_L2_IMPORT, "Received route event (%s): %s", set ? "set" : "remove", os_routing_to_string(&rbuf, &route->p));

  /* get interface name for route */
  if (route->p.if_index) {
    if_indextoname(route->p.if_index, ifname);
  }
  avl_for_each_element(&_import_tree, import, _node) {
    OONF_DEBUG(LOG_L2_IMPORT, "Check for import: %s", import->name);

    /* ignore "offlink" routes for l2net import */
    if (import->l2net && !netaddr_is_unspec(&route->p.gw)) {
      OONF_DEBUG(LOG_L2_IMPORT, "Route was not onlink");
      continue;
    }

    /* check type of route */
    if (import->rttype != OS_ROUTE_ALL && import->rttype != route->p.type) {
      OONF_DEBUG(LOG_L2_IMPORT, "Bad routing type %u (filter was %d)",
                 route->p.type, import->rttype);
      continue;
    }

    /* check prefix length */
    if (import->min_prefix_length > netaddr_get_prefix_length(&route->p.key.dst)) {
      OONF_DEBUG(LOG_L2_IMPORT, "prefix length %u is too small (filter was %d)",
                 netaddr_get_prefix_length(&route->p.key.dst), import->min_prefix_length);
      continue;
    }
    if (import->max_prefix_length < netaddr_get_prefix_length(&route->p.key.dst)) {
      OONF_DEBUG(LOG_L2_IMPORT, "prefix length %u is too large (filter was %d)",
                 netaddr_get_prefix_length(&route->p.key.dst), import->max_prefix_length);
      continue;
    }

    /* check routing table */
    if (import->table != -1 && import->table != route->p.table) {
      OONF_DEBUG(LOG_L2_IMPORT, "Bad routing table %u (filter was %d)", route->p.table, import->table);
      continue;
    }

    /* check protocol only for setting routes, its not reported for removing ones */
    if (set && import->protocol != -1 && import->protocol != route->p.protocol) {
      OONF_DEBUG(LOG_L2_IMPORT, "Bad protocol %u (filter was %d)", route->p.protocol, import->protocol);
      continue;
    }
    if (set && import->block_protocol != -1 && import->block_protocol == route->p.protocol) {
      OONF_DEBUG(LOG_L2_IMPORT, "Bad protocol %u (block was %d)", route->p.protocol, import->protocol);
      continue;
    }

    /* check metric */
    if (import->distance != -1 && import->distance != route->p.metric) {
      OONF_DEBUG(LOG_L2_IMPORT, "Bad distance %u (filter was %d)", route->p.metric, import->distance);
      continue;
    }

    /* check interface name */
    if (import->ifname[0]) {
      if (!route->p.if_index) {
        OONF_DEBUG(LOG_L2_IMPORT, "No interface set (filter was '%s')", import->ifname);
        continue;
      }
      if (strcmp(import->ifname, ifname) != 0) {
        OONF_DEBUG(LOG_L2_IMPORT, "Bad interface '%s' (filter was '%s')", ifname, import->ifname);
        continue;
      }
    }

    /* check if destination matches */
    if (!netaddr_acl_check_accept(&import->filter, &route->p.key.dst)) {
      OONF_DEBUG(LOG_L2_IMPORT, "Bad prefix %s", netaddr_to_string(&nbuf, &route->p.key.dst));
      continue;
    }

    /* see if user wants to overwrite layer2 network name */
    if (import->fixed_l2if_name[0]) {
      l2ifname = import->fixed_l2if_name;
    }
    else {
      l2ifname = ifname;
    }

    OONF_DEBUG(LOG_L2_IMPORT, "Write imported route to l2 interface %s (%s)", l2ifname, import->fixed_l2if_name);
    /* get layer2 network */
    if (set) {
      l2net = oonf_layer2_net_add(l2ifname);
    }
    else {
      l2net = oonf_layer2_net_get(l2ifname);
    }
    if (!l2net) {
      OONF_DEBUG(LOG_L2_IMPORT, "No l2 network '%s' found", l2ifname);
      continue;
    }

    dst = &route->p.key.dst;

    if (import->l2net) {
      l2local = oonf_layer2_net_get_local_ip(l2net, dst);
      if (set && l2local == NULL) {
        OONF_DEBUG(LOG_L2_IMPORT, "Set new l2net prefix: %s", netaddr_to_string(&nbuf, dst));
        oonf_layer2_net_add_ip(l2net, &import->l2origin, dst);
      }
      else if (!set && l2local != NULL) {
        OONF_DEBUG(LOG_L2_IMPORT, "Remove l2net prefix: %s", netaddr_to_string(&nbuf, dst));
        oonf_layer2_net_remove_ip(l2local, &import->l2origin);
      }
    }
    else{
      mac = NULL;
      macifname = "";
      if (import->fixed_mac_if[0]) {
        if (import->fixed_if_listener.data) {
          mac = &import->fixed_if_listener.data->mac;
          macifname = import->fixed_if_listener.data->name;
        }
      }
      else {
        mac = &l2net->if_listener.data->mac;
        macifname = l2net->if_listener.data->name;
      }
      if (netaddr_is_unspec(mac)) {
        OONF_DEBUG(LOG_L2_IMPORT, "Wait for interface (%s) data to be initialized", macifname);
        if (!oonf_timer_is_active(&_route_reload_instance)) {
          oonf_timer_set(&_route_reload_instance, 1000);
        }
        continue;
      }

      gw = &route->p.gw;

      l2neigh_ip = _remove_old_entries(l2net, import, gw, dst);
      l2neigh = NULL;
      /* get layer2 neighbor */
      if (set && !l2neigh_ip) {
        /* generate l2 key including LID */
        if (oonf_layer2_neigh_generate_lid(&nb_key, &import->l2origin, mac)) {
          OONF_WARN(LOG_L2_IMPORT, "Could not generate LID for MAC %s (if %s)",
              netaddr_to_string(&nbuf, mac), macifname);
          continue;
        }

        l2neigh = oonf_layer2_neigh_add_lid(l2net, &nb_key);
        if (!l2neigh) {
          OONF_DEBUG(LOG_L2_IMPORT, "No l2 neighbor found");
          continue;
        }

        OONF_DEBUG(LOG_L2_IMPORT, "Import layer2 neighbor...");

        /* make sure next hop is initialized */
        oonf_layer2_neigh_set_nexthop(l2neigh, gw);
        if (!oonf_layer2_neigh_get_remote_ip(l2neigh, dst)) {
          oonf_layer2_neigh_add_ip(l2neigh, &import->l2origin, dst);
        }
        oonf_layer2_neigh_commit(l2neigh);
      }
      else if (!set && l2neigh_ip) {
        l2neigh = l2neigh_ip->l2neigh;
        oonf_layer2_neigh_remove_ip(l2neigh_ip, &import->l2origin);
        oonf_layer2_neigh_commit(l2neigh);
      }
      }
  }
}

/**
 * Lookups a lan importer or create a new one
 * @param name name of lan importer
 * @return pointer to lan importer or NULL if out of memory
 */
static struct _import_entry *
_get_import(const char *name) {
  struct _import_entry *import;
  import = avl_find_element(&_import_tree, name, import, _node);
  if (import) {
    return import;
  }

  import = oonf_class_malloc(&_import_class);
  if (import == NULL) {
    return NULL;
  }

  /* copy key and add to tree */
  strscpy(import->name, name, sizeof(import->name));
  import->_node.key = import->name;
  avl_insert(&_import_tree, &import->_node);

  /* request layer2 origin */
  import->l2origin.name = import->name;
  import->l2origin.priority = OONF_LAYER2_ORIGIN_RELIABLE;
  import->l2origin.proactive = true;
  import->l2origin.lid = true;

  oonf_layer2_origin_add(&import->l2origin);

  /* initialize l2 fixed interface listener */
  import->fixed_if_listener.name = import->fixed_mac_if;

  return import;
}

/**
 * Free all resources associated with a route modifier
 * @param import import entry
 */
static void
_remove_import(struct _import_entry *import) {
  oonf_layer2_origin_remove(&import->l2origin);
  avl_remove(&_import_tree, &import->_node);
  netaddr_acl_remove(&import->filter);
  oonf_class_free(&_import_class, import);
}

/**
 * Timer for reloading routes when interface data is not finished
 * @param timer timer instance
 */
static void
_cb_reload_routes(struct oonf_timer_instance *timer __attribute__((unused))) {
  /* trigger wildcard query */
  if (!os_routing_is_in_progress(&_unicast_query)) {
    os_routing_query(&_unicast_query);
  }
}

/**
 * lan Configuration changed
 */
static void
_cb_lan_cfg_changed(void) {
  char name[20];

  snprintf(name, sizeof(name), LAN_ORIGIN_PREFIX "%s", _lan_import_section.section_name);
  _cb_cfg_changed(&_lan_import_section, name);
}

/**
 * l2import Configuration changed
 */
static void
_cb_l2_cfg_changed(void) {
  char name[20];

  snprintf(name, sizeof(name), L2IMPORT_ORIGIN_PREFIX "%s", _l2_import_section.section_name);
  _cb_cfg_changed(&_l2_import_section, name);
}

/**
 * (one of two) Configuration changed
 */
static void
_cb_cfg_changed(struct cfg_schema_section *section, char *section_name) {
  struct _import_entry *import;

  /* get existing modifier */
  import = _get_import(section_name);
  if (!import) {
    /* out of memory */
    return;
  }

  if (section->post == NULL) {
    /* section was removed */
    _remove_import(import);
    return;
  }

  /* remove old interface listener */
  os_interface_remove(&import->fixed_if_listener);

  if (cfg_schema_tobin(import, section->post, section->entries, section->entry_count)) {
    OONF_WARN(LOG_L2_IMPORT, "Could not convert configuration data of section '%s'", section->section_name);

    if (section->pre == NULL) {
      _remove_import(import);
    }
    return;
  }

  cfg_get_phy_if(import->ifname, import->ifname);
  cfg_get_phy_if(import->fixed_mac_if, import->fixed_mac_if);
  cfg_get_phy_if(import->fixed_l2if_name, import->fixed_l2if_name);

  if (!import->fixed_mac_if[0]) {
    strscpy(import->fixed_mac_if, import->ifname, IF_NAMESIZE);
  }
  if (import->fixed_mac_if[0]) {
    os_interface_add(&import->fixed_if_listener);
  }

  if (!oonf_timer_is_active(&_route_reload_instance)) {
    oonf_timer_set(&_route_reload_instance, 1000);
  }
}
