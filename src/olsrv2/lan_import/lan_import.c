
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
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/oonf.h>
#include <oonf/libcommon/list.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libcommon/netaddr_acl.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_timer.h>

#include <oonf/olsrv2/olsrv2/olsrv2.h>
#include <oonf/olsrv2/olsrv2/olsrv2_lan.h>
#include <oonf/olsrv2/olsrv2/olsrv2_routing.h>

#include <oonf/olsrv2/lan_import/lan_import.h>

/* definitions */
#define LOG_LAN_IMPORT _olsrv2_lan_import_subsystem.logging

/**
 * configuration of one LAN import instance
 */
struct _import_entry {
  /*! name of the lan import */
  char name[16];

  /*! domain of the lan import */
  int32_t domain;

  /*! address filter */
  struct netaddr_acl filter;

  /*! filter by prefix length, -1 to ignore */
  int32_t prefix_length;

  /*! filter by interface name, length null to ignore*/
  char ifname[IF_NAMESIZE];

  /*! filter by routing table id, 0 to ignore */
  int32_t table;

  /*! filter by routing protocol id, 0 to ignore */
  int32_t protocol;

  /*! filter by routing metric, 0 to ignore */
  int32_t distance;

  /*! set the routing metric to a specific value */
  int32_t routing_metric;

  /*! double the metric every time interval, 0 to disable */
  uint64_t metric_aging;

  /*! list of lan entries imported by this filter */
  struct avl_tree imported_lan_tree;

  /*! tree of all configured lan import */
  struct avl_node _node;
};

struct _imported_lan {
  struct os_route_key key;

  struct _import_entry *import;

  /*! timer to age metric value */
  struct oonf_timer_instance _aging_timer;

  /*! node for list of imported lan entries */
  struct avl_node _node;
};

/* prototypes */
static int _init(void);
static void _initiate_shutdown(void);
static void _cleanup(void);

static struct _import_entry *_get_import(const char *name);
static void _destroy_import(struct _import_entry *);

static struct _imported_lan *_add_lan(
  struct _import_entry *, struct os_route_key *key, uint32_t metric, uint8_t distance);
static void _destroy_lan(struct _imported_lan *);

static void _cb_query(struct os_route *filter, struct os_route *route);
static void _cb_query_finished(struct os_route *, int error);

static bool _is_allowed_to_import(const struct os_route *route);
static void _cb_rt_event(const struct os_route *, bool);

static void _cb_metric_aging(struct oonf_timer_instance *entry);

static void _cb_cfg_interface_changed(void);
static void _cb_cfg_changed(void);

/* plugin declaration */
static struct cfg_schema_entry _import_entries[] = {
  CFG_MAP_INT32_MINMAX(
    _import_entry, domain, "domain", "-1", "Routing domain extension for filter, -1 for all domains", 0, -1, 255),
  CFG_MAP_ACL(_import_entry, filter, "matches", ACL_DEFAULT_ACCEPT,
    "Ip addresses the filter should be applied to"
    " (the plugin will never import loopback, linklocal or multicast IPs)"),
  CFG_MAP_INT32_MINMAX(_import_entry, prefix_length, "prefix_length", "-1",
    "Prefix length the filter should be applied to, -1 for any prefix length", 0, -1, 128),
  CFG_MAP_STRING_ARRAY(
    _import_entry, ifname, "interface", "", "Interface name of matching routes, empty if all interfaces", IF_NAMESIZE),
  CFG_MAP_INT32_MINMAX(
    _import_entry, table, "table", "-1", "Routing table of matching routes, 0 for matching all tables", 0, -1, 255),
  CFG_MAP_INT32_MINMAX(
    _import_entry, protocol, "protocol", "-1", "Routing protocol of matching routes, 0 for all protocols", 0, -1, 255),
  CFG_MAP_INT32_MINMAX(
    _import_entry, distance, "metric", "-1", "Metric of matching routes, 0 for all metrics", 0, -1, INT32_MAX),
  CFG_MAP_INT32_MINMAX(_import_entry, routing_metric, "routing_metric", "1",
    "Set the routing metric of an imported route to a specific value", false, RFC7181_METRIC_MIN, RFC7181_METRIC_MAX),
  CFG_MAP_CLOCK(_import_entry, metric_aging, "metric_aging", "0",
    "Double the routing metric value every time interval, 0 to disable"),
};

static struct cfg_schema_section _interface_section = {
  CFG_OSIF_SCHEMA_INTERFACE_SECTION_INIT,

  .cb_delta_handler = _cb_cfg_interface_changed,
};

static struct cfg_schema_section _import_section = {
  .type = OONF_LAN_IMPORT_SUBSYSTEM,

  /*
   * this MUST NOT be CFG_SSMODE_NAMED_WITH_DEFAULT, otherwise it will
   * activate without user interaction
   */
  .mode = CFG_SSMODE_NAMED,

  .cb_delta_handler = _cb_cfg_changed,

  .entries = _import_entries,
  .entry_count = ARRAYSIZE(_import_entries),

  .next_section = &_interface_section,
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_CLOCK_SUBSYSTEM,
  OONF_TIMER_SUBSYSTEM,
  OONF_OLSRV2_SUBSYSTEM,
  OONF_OS_ROUTING_SUBSYSTEM,
};
static struct oonf_subsystem _olsrv2_lan_import_subsystem = {
  .name = OONF_LAN_IMPORT_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 lan-import plugin",
  .author = "Henning Rogge",

  .cfg_section = &_import_section,

  .init = _init,
  .cleanup = _cleanup,
  .initiate_shutdown = _initiate_shutdown,
};
DECLARE_OONF_PLUGIN(_olsrv2_lan_import_subsystem);

/* class definition for filters */
static struct oonf_class _import_class = {
  .name = "lan import filter",
  .size = sizeof(struct _import_entry),
};

/* class definition for imported lans */
static struct oonf_class _lan_import_class = {
  .name = "lan import entry",
  .size = sizeof(struct _imported_lan),
};

/* callback filter for dijkstra */
static struct os_route_listener _routing_listener = {
  .cb_get = _cb_rt_event,
};

/* tree of lan importers */
static struct avl_tree _import_tree;

static struct oonf_timer_class _aging_timer_class = {
  .name = "lan import metric aging",
  .callback = _cb_metric_aging,
  .periodic = true,
};

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
  oonf_class_add(&_lan_import_class);
  os_routing_listener_add(&_routing_listener);
  oonf_timer_add(&_aging_timer_class);

  /* initialize wildcard query */
  os_routing_init_wildcard_route(&_unicast_query);
  _unicast_query.cb_get = _cb_query;
  _unicast_query.cb_finished = _cb_query_finished;
  _unicast_query.p.type = OS_ROUTE_UNICAST;
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
    _destroy_import(import);
  }

  oonf_timer_remove(&_aging_timer_class);
  oonf_class_remove(&_lan_import_class);
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
 * Checks if importing the route is prevented because of safety issues
 * @param route route data
 * @return true if is okay to import, false otherwise
 */
static bool
_is_allowed_to_import(const struct os_route *route) {
  struct nhdp_domain *domain;
  const struct olsrv2_routing_domain *rtparam;
  struct os_interface *interf;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    rtparam = olsrv2_routing_get_parameters(domain);
    if (rtparam->protocol == route->p.protocol && rtparam->table == route->p.table) {
      /* do never set a LAN for a route tagged with an olsrv2 protocol */
      OONF_DEBUG(LOG_LAN_IMPORT, "Matches olsrv2 protocol, do not import!");
      return false;
    }
  }

  interf = os_interface_get_data_by_ifindex(route->p.if_index);
  if (interf != NULL && interf->flags.mesh) {
    return false;
  }
  return true;
}

/**
 * Callback for route listener
 * @param route routing data
 * @param set true if route was set, false otherwise
 */
static void
_cb_rt_event(const struct os_route *route, bool set) {
  struct _import_entry *import;
  struct _imported_lan *lan;
  char ifname[IF_NAMESIZE];
  struct os_route_key ssprefix;
  int metric;

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
  if (route->p.type != OS_ROUTE_UNICAST) {
    /* return all non-unicast type routes */
    return;
  }

  OONF_DEBUG(
    LOG_LAN_IMPORT, "Received route event (%s): %s", set ? "set" : "remove", os_routing_to_string(&rbuf, &route->p));

  if (!_is_allowed_to_import(route)) {
    return;
  }

  /* get interface name for route */
  if (route->p.if_index) {
    if_indextoname(route->p.if_index, ifname);
  }

  avl_for_each_element(&_import_tree, import, _node) {
    OONF_DEBUG(LOG_LAN_IMPORT, "Check for import: %s", import->name);

    /* check prefix length */
    if (import->prefix_length != -1 && import->prefix_length != netaddr_get_prefix_length(&route->p.key.dst)) {
      OONF_DEBUG(LOG_LAN_IMPORT, "Bad prefix length");
      continue;
    }

    /* check if destination matches */
    if (!netaddr_acl_check_accept(&import->filter, &route->p.key.dst)) {
      OONF_DEBUG(LOG_LAN_IMPORT, "Bad prefix");
      continue;
    }

    /* check routing table */
    if (import->table != -1 && import->table != route->p.table) {
      OONF_DEBUG(LOG_LAN_IMPORT, "Bad routing table");
      continue;
    }

    /* check protocol */
    if (import->protocol != -1 && import->protocol != route->p.protocol) {
      OONF_DEBUG(LOG_LAN_IMPORT, "Bad protocol");
      continue;
    }

    /* check metric */
    if (import->distance != -1 && import->distance != route->p.metric) {
      OONF_DEBUG(LOG_LAN_IMPORT, "Bad distance");
      continue;
    }

    /* check interface name */
    if (import->ifname[0]) {
      if (route->p.if_index == 0) {
        OONF_DEBUG(LOG_LAN_IMPORT, "Route has no interface");
        continue;
      }
      if (strcmp(import->ifname, ifname) != 0) {
        OONF_DEBUG(LOG_LAN_IMPORT, "Bad interface");
        continue;
      }
    }

    memcpy(&ssprefix.dst, &route->p.key.dst, sizeof(struct netaddr));
    memcpy(&ssprefix.src, &route->p.key.src, sizeof(struct netaddr));

    if (set) {
      metric = route->p.metric;
      if (metric < 1) {
        metric = 1;
      }
      if (metric > 255) {
        metric = 255;
      }

      OONF_DEBUG(LOG_LAN_IMPORT, "Add lan...");
      lan = _add_lan(import, &ssprefix, import->routing_metric, metric);
      if (lan && import->metric_aging) {
        oonf_timer_set(&lan->_aging_timer, import->metric_aging);
      }
    }
    else {
      OONF_DEBUG(LOG_LAN_IMPORT, "Remove lan...");
      lan = avl_find_element(&import->imported_lan_tree, &ssprefix, lan, _node);
      if (lan) {
        _destroy_lan(lan);
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

  avl_init(&import->imported_lan_tree, os_routing_avl_cmp_route_key, false);

  return import;
}

/**
 * Free all resources associated with a route modifier
 * @param import import entry
 */
static void
_destroy_import(struct _import_entry *import) {
  avl_remove(&_import_tree, &import->_node);
  netaddr_acl_remove(&import->filter);
  oonf_class_free(&_import_class, import);
}

static struct _imported_lan *
_add_lan(struct _import_entry *import, struct os_route_key *key, uint32_t metric, uint8_t distance) {
  struct nhdp_domain *domain;
  struct _imported_lan *lan;

  lan = avl_find_element(&import->imported_lan_tree, key, lan, _node);
  if (lan) {
    return lan;
  }

  lan = oonf_class_malloc(&_lan_import_class);
  if (!lan) {
    return NULL;
  }

  memcpy(&lan->key, key, sizeof(*key));
  lan->_node.key = &lan->key;
  avl_insert(&import->imported_lan_tree, &lan->_node);

  lan->import = import;
  lan->_aging_timer.class = &_aging_timer_class;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (import->domain == -1 || import->domain == domain->ext) {
      olsrv2_lan_add(domain, key, metric, distance);
    }
  }

  return lan;
}

static void
_destroy_lan(struct _imported_lan *lan) {
  struct nhdp_domain *domain;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (lan->import->domain == -1 || lan->import->domain == domain->ext) {
      olsrv2_lan_remove(domain, &lan->key);
    }
  }

  avl_remove(&lan->import->imported_lan_tree, &lan->_node);
  oonf_class_free(&_lan_import_class, lan);
}

static void
_cb_metric_aging(struct oonf_timer_instance *entry) {
  struct olsrv2_lan_entry *lan_entry;
  struct nhdp_domain *domain;
  struct olsrv2_lan_domaindata *landata;
  struct _imported_lan *lan;

  lan = container_of(entry, struct _imported_lan, _aging_timer);
  lan_entry = olsrv2_lan_get(&lan->key);
  if (lan_entry) {
    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      if (lan->import->domain == -1 || lan->import->domain == domain->ext) {
        landata = olsrv2_lan_get_domaindata(domain, lan_entry);
        if (landata->outgoing_metric >= RFC7181_METRIC_MAX / 2) {
          landata->outgoing_metric = RFC7181_METRIC_MAX;
          oonf_timer_stop(entry);
        }
        else {
          landata->outgoing_metric *= 2;
        }
      }
    }
  }
}

/**
 * interface section changed
 */
static void
_cb_cfg_interface_changed(void) {
  struct _import_entry *import;

  if (_interface_section.pre || !_interface_section.post) {
    /* only check for new sections */
    return;
  }

  avl_for_each_element(&_import_tree, import, _node) {
    if (import->ifname[0] && strcmp(import->ifname, _interface_section.section_name) == 0) {
      OONF_WARN(LOG_LAN_IMPORT, "Mesh interface %s cannot be used for LAN IMPORT",
                _interface_section.section_name);
    }
  }
}

/**
 * Configuration changed
 */
static void
_cb_cfg_changed(void) {
  struct _import_entry *import;

  if (_import_section.post && !_import_section.pre) {
    if (nhdp_interface_get(_import_section.section_name)) {
      OONF_WARN(LOG_LAN_IMPORT, "Mesh interface %s cannot be used for LAN IMPORT",
                _import_section.section_name);
    }
  }

  /* get existing modifier */
  import = _get_import(_import_section.section_name);
  if (!import) {
    /* out of memory */
    return;
  }

  if (_import_section.post == NULL) {
    /* section was removed */
    _destroy_import(import);
    return;
  }

  if (cfg_schema_tobin(import, _import_section.post, _import_entries, ARRAYSIZE(_import_entries))) {
    OONF_WARN(LOG_LAN_IMPORT, "Could not convert configuration data of section '%s'", _import_section.section_name);

    if (_import_section.pre == NULL) {
      _destroy_import(import);
    }
    return;
  }

  cfg_get_phy_if(import->ifname, import->ifname);

  /* trigger wildcard query */
  if (!os_routing_is_in_progress(&_unicast_query)) {
    os_routing_query(&_unicast_query);
  }
}
