
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

#include <errno.h>

#include <oonf/oonf.h>
#include <oonf/libcommon/avl.h>
#include <oonf/libcommon/avl_comp.h>
#include <oonf/libcommon/netaddr.h>
#include <oonf/libconfig/cfg_schema.h>
#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_class.h>
#include <oonf/base/oonf_layer2.h>
#include <oonf/base/os_routing.h>

#include "oonf/generic/layer2_export/layer2_export.h"

/*! logging for plugin */
#define LOG_L2EXPORT _l2export_subsystem.logging

/**
 * Additional parameters of an imported layer2 network
 */
struct _l2export_data {
  /*! originator to import, defined as the section name */
  char originator[16];

  /*! address filter */
  struct netaddr_acl filter;

  /*! filter by prefix length */
  int32_t min_prefix_length;

  /*! filter by prefix length */
  int32_t max_prefix_length;

  /*! fib distance */
  int32_t fib_distance;

  /*! fib routing table */
  int32_t fib_table;

  /*! fib protocol */
  int32_t fib_protocol;

  /*! tree of routes imported by this section */
  struct avl_tree route_tree;

  /*! node to hold all l2imports together */
  struct avl_node _node;
};

/*! Life cycle of a route exported by this plugin */
enum route_status {
  /*! nothing has been done */
  ROUTE_NOTHING,

  /*! route is currently being added to the FIB */
  ROUTE_ADDING,

  /*! route has been added to the FIB */
  ROUTE_ADDED,

  /*! route is currently being removed from the FIB */
  ROUTE_REMOVING,

  /*! route has been removed from the FIB */
  ROUTE_REMOVED,
};

/*! route object for export to FIB */
struct _l2export_route {
  /*! os route settings */
  struct os_route os;

  /*! lifecycle status of this object */
  enum route_status status;

  /*! back pointer to export data object */
  struct _l2export_data *export_data;

  /*! node for export data route tree */
  struct avl_node _node;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);
static void _initiate_shutdown(void);

static struct _l2export_data *_get_l2export(const char *name);
static void _destroy_l2export(struct _l2export_data *);
static bool _is_matching_route(struct oonf_layer2_neighbor_address *, struct _l2export_data *);

static struct _l2export_route *_get_route(struct _l2export_data *data, struct os_route_key *key);
static void _destroy_route(struct _l2export_route *route);
static void _cb_route_finished(struct os_route *route, int error);

static void _cb_l2neigh_ip_added(void *);
static void _cb_l2neigh_ip_removed(void *);

static void _cb_cfg_changed(void);

static struct cfg_schema_entry _l2export_entries[] = {
  CFG_MAP_ACL(_l2export_data, filter, "matches", ACL_DEFAULT_ACCEPT,
    "Ip addresses the filter should be applied to"
    " (the plugin will never import loopback, linklocal or multicast IPs)"),
  CFG_MAP_INT32_MINMAX(_l2export_data, min_prefix_length, "min_prefix_length", "0",
    "Minimal acceptable prefix length to import", 0, 0, 128),
  CFG_MAP_INT32_MINMAX(_l2export_data, max_prefix_length, "max_prefix_length", "128",
    "Maximum acceptable prefix length to import", 0, 0, 128),
  CFG_MAP_INT32_MINMAX(_l2export_data, fib_distance, "fib_distance", "2",
      "fib distance for exported layer2 entries", 0, 1, 255),
  CFG_MAP_INT32_MINMAX(_l2export_data, fib_table, "fib_table", "254",
      "fib table for exported layer2 entries", 0, 1, 65535),
  CFG_MAP_INT32_MINMAX(_l2export_data, fib_protocol, "fib_protocol", "100",
      "fib protocol for exported layer2 entries", 0, 1, 255),
};

static struct cfg_schema_section _l2export_section = {
  .type = OONF_LAYER2_EXPORT_SUBSYSTEM,
  .mode = CFG_SSMODE_NAMED,

  .cb_delta_handler = _cb_cfg_changed,
  .entries = _l2export_entries,
  .entry_count = ARRAYSIZE(_l2export_entries),
};

static const char *_dependencies[] = {
  OONF_CLASS_SUBSYSTEM,
  OONF_LAYER2_SUBSYSTEM,
  OONF_OS_ROUTING_SUBSYSTEM,
};
static struct oonf_subsystem _l2export_subsystem = {
  .name = OONF_LAYER2_EXPORT_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .initiate_shutdown = _initiate_shutdown,

  .cfg_section = &_l2export_section,
};
DECLARE_OONF_PLUGIN(_l2export_subsystem);

/*! tree to remember all imported layer2 originators */
static struct avl_tree _l2export_tree;

/* class definition for filters */
static struct oonf_class _l2export_class = {
  .name = "layer2 export",
  .size = sizeof(struct _l2export_data),
};

static struct oonf_class _route_class = {
  .name = "layer2 route",
  .size = sizeof(struct _l2export_route),
};

static struct oonf_class_extension _l2neighip_ext = {
  .ext_name = "l2export listener",
  .class_name = LAYER2_CLASS_NEIGHBOR_ADDRESS,

  .cb_add = _cb_l2neigh_ip_added,
  .cb_remove = _cb_l2neigh_ip_removed,
};

/* tree of routing exporters */
static struct avl_tree _l2export_tree;

/* tree of removing routes */
static struct avl_tree _removal_tree;

/**
 * Initialize plugin
 * @return always returns 0 (cannot fail)
 */
static int
_init(void) {
  if (oonf_class_extension_add(&_l2neighip_ext)) {
    return -1;
  }
  avl_init(&_l2export_tree, avl_comp_strcasecmp, false);
  avl_init(&_removal_tree, os_routing_avl_cmp_route_key, false);
  oonf_class_add(&_l2export_class);
  oonf_class_add(&_route_class);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  oonf_class_remove(&_l2export_class);
  oonf_class_extension_remove(&_l2neighip_ext);
}

/**
 * Initiate shutdown by clean up all routes
 */
static void
_initiate_shutdown(void) {
  struct _l2export_data *mod, *mod_it;

  avl_for_each_element_safe(&_l2export_tree, mod, _node, mod_it) {
    _destroy_l2export(mod);
  }
}

/**
 * Lookups a layer2 export or create a new one
 * @param name name of layer2 export
 * @return pointer to export data or NULL if out of memory
 */
static struct _l2export_data *
_get_l2export(const char *name) {
  struct _l2export_data *mod;

  mod = avl_find_element(&_l2export_tree, name, mod, _node);
  if (mod) {
    return mod;
  }

  mod = oonf_class_malloc(&_l2export_class);
  if (mod == NULL) {
    return NULL;
  }

  /* copy key and add to tree */
  strscpy(mod->originator, name, sizeof(mod->originator));
  mod->_node.key = mod->originator;
  avl_insert(&_l2export_tree, &mod->_node);

  /* initialize */
  avl_init(&mod->route_tree, os_routing_avl_cmp_route_key, false);

  return mod;
}

/**
 * Free all resources associated with a layer2 import
 * @param l2export layer2 import
 */
static void
_destroy_l2export(struct _l2export_data *l2export) {
  struct _l2export_route *l2route, *l2route_it;

  avl_for_each_element_safe(&l2export->route_tree, l2route, _node, l2route_it) {
    _destroy_route(l2route);
  }

  /* free filter resources */
  netaddr_acl_remove(&l2export->filter);

  /* first remove the import settings from the tree */
  avl_remove(&_l2export_tree, &l2export->_node);

  oonf_class_free(&_l2export_class, l2export);
}

/**
* Checks if the originator name of a l2 neighbor address matches a pattern
* @param addr l2 neighbor address
* @param pattern pattern (can end with an asterix wildcard)
* @return true if matching, false otherwise
*/
static bool
_is_matching_route(struct oonf_layer2_neighbor_address *addr, struct _l2export_data *data) {
  int len;
#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str nbuf;
#endif

  /* check prefix length */
  if (data->min_prefix_length > netaddr_get_prefix_length(&addr->ip)) {
    OONF_DEBUG(LOG_L2EXPORT, "prefix length %u is too small (filter was %d)",
               netaddr_get_prefix_length(&addr->ip), data->min_prefix_length);
    return false;
  }
  if (data->max_prefix_length < netaddr_get_prefix_length(&addr->ip)) {
    OONF_DEBUG(LOG_L2EXPORT, "prefix length %u is too large (filter was %d)",
               netaddr_get_prefix_length(&addr->ip), data->max_prefix_length);
    return false;
  }
  /* check if destination matches */
  if (!netaddr_acl_check_accept(&data->filter, &addr->ip)) {
    OONF_DEBUG(LOG_L2EXPORT, "Bad prefix %s", netaddr_to_string(&nbuf, &addr->ip));
    return false;
  }

  /* check if originator name is exact match */
  if (strcmp(addr->origin->name, data->originator) == 0) {
    return true;
  }

  /* check if originator has wildcard and is a prefix match */
  len = strlen(data->originator);
  if (len == 0 || data->originator[len-1] != '*') {
    return false;
  }

  return strncmp(addr->origin->name, data->originator, len-1) == 0;
}

/**
* Returns an existing route object or creates a new one
* @param data layer export data this route belongs to
* @param key routing key (source/destination) IP
* @return route, NULL if out of memory
*/
static struct _l2export_route *
_get_route(struct _l2export_data *data, struct os_route_key *key) {
  struct _l2export_route *l2route;

  l2route = avl_find_element(&data->route_tree, key, l2route, _node);
  if (l2route) {
    return l2route;
  }

  l2route = oonf_class_malloc(&_route_class);
  if (!l2route) {
    return NULL;
  }

  /* hook into tree */
  memcpy(&l2route->os.p.key, key, sizeof(*key));
  l2route->_node.key = &l2route->os.p.key;
  avl_insert(&data->route_tree, &l2route->_node);

  /* initialize */
  l2route->os.cb_finished = _cb_route_finished;
  l2route->export_data = data;
  return l2route;
}

/**
* triggers the removal of a route or removes the object from memory
* @param l2route route object
*/
static void
_destroy_route(struct _l2export_route *l2route) {
#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
#endif

  switch (l2route->status) {
    case ROUTE_NOTHING:
      avl_remove(&l2route->export_data->route_tree, &l2route->_node);
      oonf_class_free(&_route_class, l2route);
      break;
    case ROUTE_ADDING:
      os_routing_interrupt(&l2route->os);
      break;
      /* fallthrough */
    case ROUTE_ADDED:
      /* remove from export database */
      avl_remove(&l2route->export_data->route_tree, &l2route->_node);
      l2route->export_data = NULL;

      /* remove route */
      OONF_DEBUG(LOG_L2EXPORT, "remove route %s from fib", os_routing_to_string(&rbuf, &l2route->os.p));
      os_routing_set(&l2route->os, false, false);
      avl_insert(&_removal_tree, &l2route->_node);
      l2route->status = ROUTE_REMOVING;
      break;
    case ROUTE_REMOVING:
      /* wait for finisher */
      break;
    case ROUTE_REMOVED:
      avl_remove(&_removal_tree, &l2route->_node);
      oonf_class_free(&_route_class, l2route);
      break;
    default:
      break;
  }
}

/**
* Callback for os routing system when route handling is finished
* @param os_route route that has been finished
* @param error error code, 0 if everything is okay
*/
static void
_cb_route_finished(struct os_route *os_route, int error) {
  struct _l2export_route *l2route;
#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
#endif

  l2route = container_of(os_route, struct _l2export_route, os);

  OONF_DEBUG(LOG_L2EXPORT, "route finished (error=%d, status=%d): %s",
      error, l2route->status, os_routing_to_string(&rbuf, &os_route->p));
  switch (l2route->status) {
    case ROUTE_ADDING:
      l2route->status = ROUTE_ADDED;
      if (error) {
        _destroy_route(l2route);
      }
      break;
    case ROUTE_REMOVING:
      l2route->status = ROUTE_REMOVED;
      _destroy_route(l2route);
      break;
    default:
      OONF_WARN(LOG_L2EXPORT, "Got route feedback for state %d", l2route->status);
      _destroy_route(l2route);
      break;
  }
}

/**
* Callback triggered when a l2 neighbor address is addrd
* @param ptr address being added
*/
static void
_cb_l2neigh_ip_added(void *ptr) {
  struct oonf_layer2_neighbor_address *nip = ptr;
  struct _l2export_data *l2export;
  struct _l2export_route *l2route;
  struct os_route_key rt_key;
  int8_t af;
#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
  struct netaddr_str nbuf;
#endif
  os_routing_init_sourcespec_prefix(&rt_key, &nip->ip);

  avl_for_each_element(&_l2export_tree, l2export, _node) {
    OONF_DEBUG(LOG_L2EXPORT, "Check export %s against originator %s",
                   l2export->originator, nip->origin->name);
    if (_is_matching_route(nip, l2export)) {
      OONF_DEBUG(LOG_L2EXPORT, "match");
      l2route = _get_route(l2export, &rt_key);
      if (!l2route) {
        continue;
      }

      OONF_DEBUG(LOG_L2EXPORT, "got entry");

      // TODO: what if this route is not in state "nothing" ?
      af = netaddr_get_address_family(&nip->ip);

      /* set route parameters */
      l2route->os.p.family = af;
      memcpy(&l2route->os.p.gw, oonf_layer2_neigh_get_nexthop(nip->l2neigh, af), sizeof(struct netaddr));
      l2route->os.p.type = OS_ROUTE_UNICAST;
      l2route->os.p.metric   = l2export->fib_distance;
      l2route->os.p.if_index = nip->l2neigh->network->if_listener.data->index;
      l2route->os.p.protocol = l2export->fib_protocol;
      l2route->os.p.table    = l2export->fib_table;

      OONF_DEBUG(LOG_L2EXPORT, "Add route %s to fib (gw was %s)",
          os_routing_to_string(&rbuf, &l2route->os.p),
          netaddr_to_string(&nbuf, oonf_layer2_neigh_get_nexthop(nip->l2neigh, af)));
      if (!os_routing_set(&l2route->os, true, true)) {
        l2route->status = ROUTE_ADDING;
      }
    }
  }
}

/**
* Callback triggered when a l2 neighbor address is removed
* @param ptr address being removed
*/
static void
_cb_l2neigh_ip_removed(void *ptr) {
  struct oonf_layer2_neighbor_address *nip = ptr;
  struct _l2export_data *l2export;
  struct _l2export_route *l2route;
  struct os_route_key rt_key;

  os_routing_init_sourcespec_prefix(&rt_key, &nip->ip);

  avl_for_each_element(&_l2export_tree, l2export, _node) {
    OONF_DEBUG(LOG_L2EXPORT, "Check export %s against originator %s",
               l2export->originator, nip->origin->name);
    if (_is_matching_route(nip, l2export)) {
      OONF_DEBUG(LOG_L2EXPORT, "match");
      l2route = avl_find_element(&l2export->route_tree, &rt_key, l2route, _node);
      if (l2route) {
        OONF_DEBUG(LOG_L2EXPORT, "found entry");
        _destroy_route(l2route);
      }
    }
  }
}

/**
 * Configuration changed
 */
static void
_cb_cfg_changed(void) {
  struct _l2export_data *l2export;

  /* get existing import */
    l2export = _get_l2export(_l2export_section.section_name);
  if (!l2export) {
    /* out of memory */
    return;
  }

  if (!_l2export_section.post) {
    /* section was removed */
        _destroy_l2export(l2export);
    return;
  }

  if (cfg_schema_tobin(l2export, _l2export_section.post, _l2export_entries, ARRAYSIZE(_l2export_entries))) {
    OONF_WARN(LOG_L2EXPORT,
        "Could not convert configuration data of section '%s'", _l2export_section.section_name);

    if (!_l2export_section.pre) {
            _destroy_l2export(l2export);
    }
    return;
  }
}
