
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
#include <oonf/generic/layer2_import/layer2_import.h>
#include <oonf/olsrv2/olsrv2/olsrv2_lan.h>

#include <oonf/olsrv2/olsrv2_l2import/olsrv2_l2import.h>

/*! logging for plugin */
#define LOG_L2IMPORT _l2import_subsystem.logging

/*! locally attached network option for source-specific prefix */
#define LAN_DEFAULT_DOMAIN -1

/**
 * Additional parameters of an imported layer2 network
 */
struct _l2export_data {
  /*! originator to import, defined as the section name */
  char originator[24];

  /*! domain for import, -1 for all domains */
  int32_t domain;

  /*! routing metric for import, -1 to attempt calculating from layer2 database */
  int32_t routing_metric;

  /*! fib distance entry for import */
  int32_t fib_distance;

  /*! node to hold all l2imports together */
  struct avl_node _node;
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static struct _l2export_data *_get_l2export(const char *name);
static void _destroy_l2export(struct _l2export_data *);
static bool _is_matching_origin(struct oonf_layer2_neighbor_address *, const char *pattern);

static void _remove_l2neighip_lans(struct oonf_layer2_neighbor_address *nip);

static void _cb_l2neigh_ip_added(void *);
static void _cb_l2neigh_ip_removed(void *);

static void _cb_cfg_changed(void);

static struct cfg_schema_entry _l2import_entries[] = {
  CFG_MAP_INT32_MINMAX(_l2export_data, domain, "domain", "-1",
      "domain for the imported LAN entries, -1 for all domains", 0, -1, NHDP_MAXIMUM_DOMAINS),
  CFG_MAP_INT32_MINMAX(_l2export_data, routing_metric, "metric", "-1",
      "routing metric for the imported LAN entries, -1 to calculate from layer2 data", 0, -1, RFC7181_METRIC_MAX),
  CFG_MAP_INT32_MINMAX(_l2export_data, fib_distance, "fib_distance", "2",
      "fib distance for imported LAN entries", 0, 1, 255),
};

static struct cfg_schema_section _l2import_section = {
  .type = OONF_OLSRV2_L2IMPORT_SUBSYSTEM,
  .mode = CFG_SSMODE_NAMED_WITH_DEFAULT,
  .def_name = LAN_ORIGIN_PREFIX "*",

  .cb_delta_handler = _cb_cfg_changed,
  .entries = _l2import_entries,
  .entry_count = ARRAYSIZE(_l2import_entries),
};

static const char *_dependencies[] = {
  OONF_OLSRV2_SUBSYSTEM,
};
static struct oonf_subsystem _l2import_subsystem = {
  .name = OONF_OLSRV2_L2IMPORT_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .init = _init,
  .cleanup = _cleanup,
  .cfg_section = &_l2import_section,
};
DECLARE_OONF_PLUGIN(_l2import_subsystem);

/*! tree to remember all imported layer2 originators */
static struct avl_tree _l2export_tree;

/* class definition for filters */
static struct oonf_class _l2export_class = {
  .name = "olsrv2 l2import",
  .size = sizeof(struct _l2export_data),
};

static struct oonf_class_extension _l2neighip_ext = {
  .ext_name = "l2import listener",
  .class_name = LAYER2_CLASS_NEIGHBOR_ADDRESS,

  .cb_add = _cb_l2neigh_ip_added,
  .cb_remove = _cb_l2neigh_ip_removed,
};

/* tree of routing filters */
static struct avl_tree _l2export_tree;

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
  oonf_class_add(&_l2export_class);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  struct _l2export_data *mod, *mod_it;

  avl_for_each_element_safe(&_l2export_tree, mod, _node, mod_it) {
        _destroy_l2export(mod);
  }

  oonf_class_remove(&_l2export_class);
  oonf_class_extension_remove(&_l2neighip_ext);
}

/**
 * Lookups a layer2 import or create a new one
 * @param name name of layer2 import
 * @return pointer to import data or NULL if out of memory
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

  OONF_DEBUG(LOG_L2IMPORT, "Adding import-origin '%s'", name);
  return mod;
}

/**
 * Free all resources associated with a layer2 import
 * @param l2import layer2 import
 */
static void
_destroy_l2export(struct _l2export_data *l2import) {
  struct oonf_layer2_neighbor_address *l2nip;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_net *l2net;

  /* first remove the import settings from the tree */
  avl_remove(&_l2export_tree, &l2import->_node);

  avl_for_each_element(oonf_layer2_get_net_tree(), l2net, _node) {
    avl_for_each_element(&l2net->neighbors, l2neigh, _node) {
      avl_for_each_element(&l2neigh->remote_neighbor_ips, l2nip, _neigh_node) {
        if (strcmp(l2nip->origin->name, l2import->originator) == 0) {
          _remove_l2neighip_lans(l2nip);
        }
      }
    }
  }

  OONF_DEBUG(LOG_L2IMPORT, "Removing import-origin '%s'", l2import->originator);

  // TODO: iterate over the l2 database if we need to remove something from the olsrv2 LAN database
  oonf_class_free(&_l2export_class, l2import);
}

static bool
_is_matching_origin(struct oonf_layer2_neighbor_address *addr, const char *pattern) {
  int len;
  bool result;

  if (strcmp(addr->origin->name, pattern) == 0) {
    OONF_DEBUG(LOG_L2IMPORT, "Exact origin match: '%s'", addr->origin->name);

    return true;
  }

  len = strlen(pattern);
  if (len == 0 || pattern[len-1] != '*') {
    OONF_DEBUG(LOG_L2IMPORT, "No origin match: '%s' != '%s'", addr->origin->name, pattern);
    return false;
  }

  result = strncmp(addr->origin->name, pattern, len-1) == 0;
  OONF_DEBUG(LOG_L2IMPORT, "Origin pattern cmp: '%s' %s '%s'",
             addr->origin->name, result ? "==" : "!=", pattern);
  return result;
}

static void
_remove_l2neighip_lans(struct oonf_layer2_neighbor_address *nip) {
  struct _l2export_data *l2import;
  struct os_route_key rt_key;
  struct nhdp_domain *domain;

#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
  os_routing_init_sourcespec_prefix(&rt_key, &nip->ip);
#endif

  avl_for_each_element(&_l2export_tree, l2import, _node) {
    if (_is_matching_origin(nip, l2import->originator)) {
      if (l2import->domain >= 0) {
        domain = nhdp_domain_get_by_ext(l2import->domain);

        OONF_DEBUG(LOG_L2IMPORT, "Remove lan (%d): %s", l2import->domain,
                   os_routing_key_to_string(&rbuf, &rt_key));

        olsrv2_lan_remove(domain, &rt_key);
      }
      else {
        OONF_DEBUG(LOG_L2IMPORT, "Remove lan (all): %s",
                   os_routing_key_to_string(&rbuf, &rt_key));

        list_for_each_element(nhdp_domain_get_list(), domain, _node) {
          olsrv2_lan_remove(domain, &rt_key);
        }
      }
    }
  }
}

static void
_cb_l2neigh_ip_added(void *ptr) {
  struct oonf_layer2_neighbor_address *nip = ptr;
  struct _l2export_data *l2import;
  struct os_route_key rt_key;
  struct nhdp_domain *domain;
  uint32_t metric;
  int32_t distance;

#ifdef OONF_LOG_DEBUG_INFO
  struct os_route_str rbuf;
#endif
  os_routing_init_sourcespec_prefix(&rt_key, &nip->ip);

  avl_for_each_element(&_l2export_tree, l2import, _node) {
    if (_is_matching_origin(nip, l2import->originator)) {
      distance = l2import->fib_distance;

      if (l2import->domain >= 0) {
        domain = nhdp_domain_get_by_ext(l2import->domain);
        metric = 1;
        if (l2import->routing_metric < (int)RFC7181_METRIC_MIN) {
          nhdp_domain_get_metric(domain, &metric, nip->l2neigh);
        }
        else {
          metric = l2import->routing_metric;
        }

        OONF_DEBUG(LOG_L2IMPORT, "Add lan (%d): %s", l2import->domain,
                   os_routing_key_to_string(&rbuf, &rt_key));
        olsrv2_lan_add(domain, &rt_key, metric , distance);
      }
      else {
        OONF_DEBUG(LOG_L2IMPORT, "Add lan (all): %s",
                   os_routing_key_to_string(&rbuf, &rt_key));
        list_for_each_element(nhdp_domain_get_list(), domain, _node) {
          metric = 1;
          if (l2import->routing_metric < (int)RFC7181_METRIC_MIN) {
            nhdp_domain_get_metric(domain, &metric, nip->l2neigh);
          }
          else {
            metric = l2import->routing_metric;
          }

          olsrv2_lan_add(domain, &rt_key, metric , distance);
        }
      }
    }
  }
}

static void
_cb_l2neigh_ip_removed(void *ptr) {
  _remove_l2neighip_lans(ptr);
}

/**
 * Configuration changed
 */
static void
_cb_cfg_changed(void) {
  struct _l2export_data *l2import;

  /* get existing import */
  l2import = _get_l2export(_l2import_section.section_name);
  if (!l2import) {
    /* out of memory */
    return;
  }

  if (!_l2import_section.post) {
    /* section was removed */
        _destroy_l2export(l2import);
    return;
  }

  if (cfg_schema_tobin(l2import, _l2import_section.post, _l2import_entries, ARRAYSIZE(_l2import_entries))) {
    OONF_WARN(LOG_L2IMPORT,
        "Could not convert configuration data of section '%s'", _l2import_section.section_name);

    if (!_l2import_section.pre) {
            _destroy_l2export(l2import);
    }
    return;
  }

  if (!_l2import_section.pre) {
    // TODO: iterate over the l2 database if we need to remove something from the olsrv2 LAN database
  }
}
