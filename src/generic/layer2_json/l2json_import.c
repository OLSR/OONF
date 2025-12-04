
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
#include <jansson.h>

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

#include <oonf/generic/layer2_json/layer2_json.h>
#include <oonf/generic/layer2_json/layer2_json_internal.h>

struct l2json_origin {
  struct oonf_layer2_origin origin;
  char name[32];
  struct list_entity _node;
};

static int _import_l2net(json_error_t *error, json_t *j_net);
static bool _is_array_or_null(json_t *j);

static struct oonf_class _origin_class = {
  .name = "l2json origin",
  .size = sizeof(struct l2json_origin)
};

static struct list_entity _origin_list;
static enum oonf_log_source LOG_LAYER2_JSON;

void
l2json_import_init(enum oonf_log_source log) {
  LOG_LAYER2_JSON = log;

  oonf_class_add(&_origin_class);
  list_init_head(&_origin_list);
}

void l2json_import_cleanup(void) {
  struct l2json_origin *ptr, *safe;

  list_for_each_element_safe(&_origin_list, ptr, _node, safe) {
    list_remove(&ptr->_node);
    oonf_class_free(&_origin_class, ptr);
  }

  oonf_class_remove(&_origin_class);
}

int
l2json_import(struct oonf_telnet_data __attribute__((unused)) *con,
                  const char *input) {
  json_t *root, *j_nets, *j_net;
  json_error_t error;
  size_t idx;
  int rc;

  rc = -1;

  OONF_DEBUG(LOG_LAYER2_JSON, "Import: '%s'", input);
  root = json_loads(input, JSON_REJECT_DUPLICATES, &error);
  if (!root) {
    goto import_fail;
  }

  if (json_unpack_ex(root, &error, sizeof(error),
                     "{so}",
                     "interfaces", &j_nets)) {
    OONF_DEBUG(LOG_LAYER2_JSON, "Error:(%s/%s)",
               error.text, error.source);
    goto import_fail;
  }

  if (!_is_array_or_null(j_nets)) {
    goto import_fail;
  }

  json_array_foreach(j_nets, idx, j_net) {
    if ((rc = _import_l2net(&error, j_net))) {
      OONF_DEBUG(LOG_LAYER2_JSON, "Error: %d (%s/%s)",
                 rc, error.text, error.source);
      goto import_fail;
    }
  }
  rc = 0;

import_fail:
  json_decref(root);
  return rc;
}

static struct oonf_layer2_origin *
_get_origin(const char *name) {
  struct oonf_layer2_origin *origin;
  struct l2json_origin *jsonorigin;

  origin = oonf_layer2_origin_get(name);
  if (origin) {
    return origin;
  }
  jsonorigin = oonf_class_malloc(&_origin_class);
  if (!jsonorigin) {
    return NULL;
  }
  list_add_tail(&_origin_list, &jsonorigin->_node);
  strscpy(jsonorigin->name, name, sizeof(jsonorigin->name));
  jsonorigin->origin.name = jsonorigin->name;

  oonf_layer2_origin_add(&jsonorigin->origin);
  return &jsonorigin->origin;
}

static bool
_is_array_or_null(json_t *j) {
  return j == NULL || json_is_array(j);
}

static int
_import_local_peer(json_error_t *error,
    struct oonf_layer2_net *l2net, json_t *j_ip) {
  struct oonf_layer2_origin *l2origin;
  struct netaddr ipbuf;
  char *ip, *origin;

  if(json_unpack_ex(j_ip, error, sizeof(*error),
                    "{ss ss}",
                    "ip", &ip,
                    "origin", &origin)) {
    return __LINE__;
  }

  if (netaddr_from_string(&ipbuf, ip)) {
    return __LINE__;
  }

  l2origin = _get_origin(origin);
  if (!l2origin) {
    return __LINE__;
  }

  if(!oonf_layer2_net_add_ip(l2net, l2origin, &ipbuf)) {
    return __LINE__;
  }
  return 0;
}

static int
_import_destination(json_error_t *error,
    struct oonf_layer2_neigh *l2neigh, json_t *j_dst) {
  struct oonf_layer2_origin *l2origin;
  struct netaddr ipbuf;
  char *ip, *origin;

  if(json_unpack_ex(j_dst, error, sizeof(*error),
                    "{ss ss}",
                    "addr", &ip,
                    "origin", &origin)) {
    return __LINE__;
  }

  if (netaddr_from_string(&ipbuf, ip)) {
    return __LINE__;
  }

  l2origin = _get_origin(origin);
  if (!l2origin) {
    return __LINE__;
  }

  if(!oonf_layer2_destination_add(l2neigh, &ipbuf, l2origin)) {
    return __LINE__;
  }
  return 0;
}

static int
_import_remoteip(json_error_t *error,
    struct oonf_layer2_neigh *l2neigh, json_t *j_rip) {
  struct oonf_layer2_origin *l2origin;
  struct netaddr ipbuf;
  char *ip, *origin;

  if(json_unpack_ex(j_rip, error, sizeof(*error),
                    "{ss ss}",
                    "addr", &ip,
                    "origin", &origin)) {
    return __LINE__;
  }

  if (netaddr_from_string(&ipbuf, ip)) {
    return __LINE__;
  }

  l2origin = _get_origin(origin);
  if (!l2origin) {
    return __LINE__;
  }

  if(!oonf_layer2_neigh_add_ip(l2neigh, l2origin, &ipbuf)) {
    return __LINE__;
  }
  return 0;
}

static int
_set_data(struct oonf_layer2_data *data,
    const struct oonf_layer2_metadata *meta, const char *originname,
    const char *value, int64_t intvalue, bool boolvalue) {
  struct oonf_layer2_origin *origin;
  union oonf_layer2_value l2value;

  origin = _get_origin(originname);
  if (!origin) {
    return __LINE__;
  }

  if (value) {
    if (oonf_layer2_data_parse_string(&l2value, meta, value)) {
      OONF_WARN(LOG_LAYER2_JSON, "%s: %s", meta->key, value);
      return __LINE__;
    }
  }
  else if (meta->type == OONF_LAYER2_INTEGER_DATA) {
    l2value.integer = intvalue;
  }
  else if (meta->type == OONF_LAYER2_BOOLEAN_DATA) {
    l2value.boolean = boolvalue;
  }
  else {
    return __LINE__;
  }

  oonf_layer2_data_set(data, origin, meta, &l2value);
  return 0;
}

static int
_import_net_data(json_error_t *error, struct oonf_layer2_data *data,
    json_t *j_netdata) {
  const struct oonf_layer2_metadata *meta;
  enum oonf_layer2_network_index idx;
  char *key, *origin, *value;
  int64_t intvalue;
  bool boolvalue;

  key = NULL;
  origin = NULL;
  value = NULL;
  intvalue = 0;
  boolvalue = false;

  if (json_unpack_ex(j_netdata, error, sizeof(*error),
                     "{ss ss s?s s?I s?b}",
                     "key", &key,
                     "origin", &origin,
                     "value", &value,
                     "intvalue", &intvalue,
                     "boolvalue", &boolvalue
      )) {
    return __LINE__;
  }

  for (idx = 0; idx<OONF_LAYER2_NET_COUNT; idx++) {
    meta = oonf_layer2_net_metadata_get(idx);
    if (strcmp(meta->key, key) == 0) {
      return _set_data(&data[idx], meta, origin, value, intvalue, boolvalue);
    }
  }
  return __LINE__;
}

static int
_import_neigh_data(json_error_t *error, struct oonf_layer2_data *data,
    json_t *j_netdata) {
  const struct oonf_layer2_metadata *meta;
  enum oonf_layer2_neighbor_index idx;
  char *key, *origin, *value;
  int64_t intvalue;
  bool boolvalue;

  key = NULL;
  origin = NULL;
  value = NULL;
  intvalue = 0;
  boolvalue = false;

  if (json_unpack_ex(j_netdata, error, sizeof(*error),
                     "{ss ss s?s s?I s?b}",
                     "key", &key,
                     "origin", &origin,
                     "value", &value,
                     "intvalue", &intvalue,
                     "boolvalue", &boolvalue
      )) {
    return __LINE__;
  }

  for (idx = 0; idx<OONF_LAYER2_NEIGH_COUNT; idx++) {
    meta = oonf_layer2_neigh_metadata_get(idx);
    if (strcmp(meta->key, key) == 0) {
      return _set_data(&data[idx], meta, origin, value, intvalue, boolvalue);
    }
  }
  return __LINE__;
}

static int
_import_l2neigh(json_error_t *error, json_t *j_neigh,
    struct oonf_layer2_net *l2net) {
  char *addr, *link_id_str;
  char *next4, *next6;
  json_t *j_dest, *j_remoteip;
  int64_t last_seen;
  json_t *j_neighdata;

  json_t *j_item;
  size_t idx;
  int rc;

  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_neigh_key key;
  ssize_t len;

  memset(&key, 0, sizeof(key));

  link_id_str = NULL;
  next4 = NULL;
  next6 = NULL;

  if(json_unpack_ex(j_neigh, error, sizeof(*error),
                    "{s{ss s?s} s?s s?s s?I s?o s?o s?o}",
                    "key",
                    "addr", &addr,
                    "link_id", &link_id_str,
                    "ll_ipv4", &next4,
                    "ll_ipv6", &next6,
                    "last_seen", &last_seen,
                    "proxy_addr", &j_dest,
                    "remote_ip", &j_remoteip,
                    "data", &j_neighdata)) {
    return __LINE__;
  }

  if (netaddr_from_string(&key.addr, addr)) {
    OONF_WARN(LOG_LAYER2_JSON, "Bad neighbor key: %s", addr);
    return __LINE__;
  }
  if (link_id_str) {
    len = strhex_to_bin(key.link_id, sizeof(key.link_id), link_id_str);
    if (len < 0 || len > OONF_LAYER2_MAX_LINK_ID) {
      OONF_WARN(LOG_LAYER2_JSON, "Bad link_id for neighbor %s: %s", addr, link_id_str);
      return __LINE__;
    }
    key.link_id_length = len;
  }

  if (!(l2neigh = oonf_layer2_neigh_add_lid(l2net, &key))) {
    return __LINE__;
  }

  if (next4) {
    if (netaddr_from_string(&l2neigh->_next_hop_v4, next4)) {
      OONF_WARN(LOG_LAYER2_JSON, "Bad ll_ipv4 for neighbor (%s/%s): %s",
                addr, link_id_str, next4);
      return __LINE__;
    }
  }
  if (next6) {
    if (netaddr_from_string(&l2neigh->_next_hop_v6, next6)) {
      OONF_WARN(LOG_LAYER2_JSON, "Bad ll_ipv6 for neighbor (%s/%s): %s",
                addr, link_id_str, next6);
      return __LINE__;
    }
  }

  if (last_seen) {
    l2net->last_seen = oonf_clock_get_absolute(-last_seen);
  }

  if (j_dest) {
    json_array_foreach(j_dest, idx, j_item) {
      if ((rc = _import_destination(error, l2neigh, j_item))) {
        return rc;
      }
    }
  }

  if (j_remoteip) {
    json_array_foreach(j_remoteip, idx, j_item) {
      if ((rc = _import_remoteip(error, l2neigh, j_item))) {
        return rc;
      }
    }
  }

  if (j_neighdata) {
    json_array_foreach(j_neighdata, idx, j_item) {
      if ((rc = _import_neigh_data(error, &l2neigh->data[0], j_item))) {
        return rc;
      }
    }
  }
  return 0;
}

static int
_import_l2net(json_error_t *error, json_t *j_net) {
  const char *name, *if_ident, *if_type;
  int if_dlep;
  int64_t last_seen;
  json_t *j_ips, *j_netdata, *j_neighdata, *j_neighs, *j_item;
  size_t idx;
  int rc;
  struct oonf_layer2_net *l2net;

  name = NULL;
  if_ident = NULL;
  if_type = NULL;
  if_dlep = -1;
  last_seen = 0;
  j_ips = NULL;
  j_netdata = NULL;
  j_neighdata = NULL;
  j_neighs = NULL;
  if(json_unpack_ex(j_net, error, sizeof(*error),
                    "{ss s?s s?s s?b s?I s?o s?o s?o s?o}",
                    "name", &name,
                    "ident", &if_ident,
                    "type", &if_type,
                    "dlep", &if_dlep,
                    "last_seen", &last_seen,
                    "local_peers", &j_ips,
                    "data", &j_netdata,
                    "neighbor_defaults", &j_neighdata,
                    "neighbors", &j_neighs)) {
    return __LINE__;
  }
  if (!_is_array_or_null(j_ips)) {
    return __LINE__;
  }
  if (!_is_array_or_null(j_netdata)) {
    return __LINE__;
  }
  if (!_is_array_or_null(j_neighdata)) {
    return __LINE__;
  }
  if (!_is_array_or_null(j_neighs)) {
    return __LINE__;
  }

  l2net = oonf_layer2_net_add(name);
  if (!l2net) {
    return __LINE__;
  }
  if (if_ident) {
    strscpy(l2net->if_ident, if_ident, sizeof(l2net->if_ident));
  }
  if (if_type) {
    l2net->if_type = oonf_layer2_get_type(if_type);
  }
  if (if_dlep != -1) {
    l2net->if_dlep = if_dlep != 0;
  }
  if (last_seen) {
    l2net->last_seen = oonf_clock_get_absolute(-last_seen);
  }
  if (j_ips) {
    json_array_foreach(j_ips, idx, j_item) {
      if ((rc = _import_local_peer(error, l2net, j_item))) {
        return rc;
      }
    }
  }
  if (j_netdata) {
    json_array_foreach(j_netdata, idx, j_item) {
      if ((rc = _import_net_data(error, &l2net->data[0], j_item))) {
        return rc;
      }
    }
  }
  if (j_neighdata) {
    json_array_foreach(j_neighdata, idx, j_item) {
      if ((rc = _import_neigh_data(error, &l2net->neighdata[0], j_item))) {
        return rc;
      }
    }
  }
  if (j_neighs) {
    json_array_foreach(j_neighs, idx, j_item) {
      if ((rc = _import_l2neigh(error, j_item, l2net))) {
        return rc;
      }
    }
  }
  return 0;
}
