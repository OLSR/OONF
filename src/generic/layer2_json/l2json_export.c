
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

#include <oonf/generic/layer2_json/layer2_json_internal.h>

static int _export_root(json_error_t *error, json_t *root);
static int _cb_dump(const char *buffer, size_t size, void *data);

static enum oonf_log_source LOG_LAYER2_JSON;

void
l2json_export_init(enum oonf_log_source log) {
  LOG_LAYER2_JSON = log;
}

void
l2json_export_cleanup(void) {
}

int l2json_export(struct oonf_telnet_data *con) {
  json_t *root;
  json_error_t error;
  int rc;

  rc = -1;
  root = json_object();
  if (!root) {
    goto export_fail;
  }

  if ((rc = _export_root(&error, root))) {
    OONF_DEBUG(LOG_LAYER2_JSON, "Error: %d (%s/%s)",
               rc, error.text, error.source);
    goto export_fail;
  }

  if (json_dump_callback(root, _cb_dump, con, JSON_ENSURE_ASCII)) {
    goto export_fail;
  }

  abuf_puts(con->out, "\n");

  rc = 0;

export_fail:
  json_decref(root);
  return rc;
}

static int
_add_data_object(json_error_t *error,
                 json_t *array, struct oonf_layer2_data *l2data,
    const struct oonf_layer2_metadata *l2meta) {
  const struct oonf_layer2_origin *l2origin;
  char l2vbuf[256];

  if (!oonf_layer2_data_has_value(l2data)) {
    /* skip this data object */
    return 0;
  }

  l2origin = oonf_layer2_data_get_origin(l2data);
  if (!oonf_layer2_data_to_string(l2vbuf, sizeof(l2vbuf), l2data, l2meta, false)) {
    return __LINE__;
  }

  switch (oonf_layer2_data_get_type(l2data)) {
    case OONF_LAYER2_INTEGER_DATA:
      if (json_array_append_new(array,
          json_pack_ex(error, sizeof(*error),
                      "{ss ss ss sI ss ss sI}",
                      "type", oonf_layer2_data_get_type_string(l2meta),
                      "key", l2meta->key,
                      "value", l2vbuf,
                      "intvalue", oonf_layer2_data_get_int64(l2data, 0, 0),
                      "origin", l2origin->name,
                      "unit", l2meta->unit,
                      "scaling", l2meta->scaling
          ))) {
        return __LINE__;
      }
      break;
    case OONF_LAYER2_BOOLEAN_DATA:
      if (json_array_append_new(array,
          json_pack_ex(error, sizeof(*error),
                      "{ss ss ss sb ss}",
                      "type", oonf_layer2_data_get_type_string(l2meta),
                      "key", l2meta->key,
                      "value", l2vbuf,
                      "boolvalue", oonf_layer2_data_get_boolean(l2data, false),
                      "origin", l2origin->name
          ))) {
        return __LINE__;
      }
      break;
    default:
      if (json_array_append_new(array,
          json_pack_ex(error, sizeof(*error),
                       "{ss ss ss ss}",
                       "type", oonf_layer2_data_get_type_string(l2meta),
                       "key", l2meta->key,
                       "value", l2vbuf,
                       "origin", l2origin->name
          ))) {
        return __LINE__;
      }
      break;
  }
  return 0;
}

static int
_export_l2neigh(json_error_t *error,
                json_t *j_neighs, struct oonf_layer2_neigh *l2neigh) {
  struct oonf_layer2_neighbor_address *l2remoteip;
  struct oonf_layer2_destination *l2proxy;
  struct oonf_layer2_data *l2data;
  const struct oonf_layer2_metadata *l2meta;
  enum oonf_layer2_neighbor_index neighidx;
  int result;
  const char *ll4, *ll6;
  struct netaddr_str nbuf1, nbuf2, nbuf3;
  char hexbuf[OONF_LAYER2_MAX_LINK_ID*3];
  int64_t lastseen;

  json_t *j_proxy;
  json_t *j_remoteip;
  json_t *j_neighdata;

  j_proxy = json_array();
  j_remoteip = json_array();
  j_neighdata = json_array();

  if (-1 == strhex_from_bin(hexbuf, sizeof(hexbuf),
                            l2neigh->key.link_id,
                            l2neigh->key.link_id_length)) {
    return __LINE__;
  }
  ll4 = NULL;
  if (oonf_layer2_neigh_has_nexthop(l2neigh, AF_INET)) {
    ll4 = netaddr_to_string(&nbuf2, oonf_layer2_neigh_get_nexthop(l2neigh, AF_INET));
  }
  ll6 = NULL;
  if (oonf_layer2_neigh_has_nexthop(l2neigh, AF_INET6)) {
    ll6 = netaddr_to_string(&nbuf3, oonf_layer2_neigh_get_nexthop(l2neigh, AF_INET6));
  }
  lastseen = -oonf_clock_get_relative(
    oonf_layer2_neigh_get_lastseen(l2neigh)
  );
  if (json_array_append_new(j_neighs,
      json_pack_ex(error, sizeof(*error),
                   "{s{ss ss} ss* ss* sI so so so}",
                   "key",
                   "addr", netaddr_to_string(&nbuf1, &l2neigh->key.addr),
                   "link_id", hexbuf,
                   "ll_ipv4", ll4,
                   "ll_ipv6", ll6,
                   "last_seen", lastseen,
                   "proxy_addr", j_proxy,
                   "remote_ip", j_remoteip,
                   "data", j_neighdata
          ))) {
    return __LINE__;
  }

  avl_for_each_element(&l2neigh->destinations, l2proxy, _node) {
    if (json_array_append_new(j_proxy,
        json_pack_ex(error, sizeof(*error),
                     "{ss ss}",
                     "addr", netaddr_to_string(&nbuf1, &l2proxy->destination),
                     "origin", l2proxy->origin->name
        ))) {
      return __LINE__;
    }
  }

  avl_for_each_element(&l2neigh->remote_neighbor_ips, l2remoteip, _neigh_node) {
    if (json_array_append_new(j_remoteip,
        json_pack("{ss ss}",
                  "addr", netaddr_to_string(&nbuf1, &l2remoteip->ip),
                  "origin", l2remoteip->origin->name
        ))) {
      return __LINE__;
    }
  }

  for (neighidx = 0; neighidx < OONF_LAYER2_NEIGH_COUNT; neighidx++) {
    l2data = &l2neigh->data[neighidx];
    l2meta = oonf_layer2_neigh_metadata_get(neighidx);
    if ((result =_add_data_object(error, j_neighdata, l2data, l2meta))) {
      return result;
    }
  }
  return 0;
}

static int
_export_l2net(json_error_t *error,
              json_t *j_nets, struct oonf_layer2_net *l2net) {
  struct oonf_layer2_peer_address *l2peer;
  struct oonf_layer2_neigh *l2neigh;
  struct oonf_layer2_data *l2data;
  const struct oonf_layer2_metadata *l2meta;
  enum oonf_layer2_network_index netidx;
  enum oonf_layer2_neighbor_index neighidx;
  int result;

  json_t *j_ips, *j_neighs;
  json_t *j_netdata, *j_neighdata;

  struct netaddr_str nbuf;
  j_ips = json_array();
  j_netdata = json_array();
  j_neighdata = json_array();
  j_neighs = json_array();

  if (json_array_append_new(j_nets,
      json_pack_ex(error, sizeof(*error),
                   "{ss ss ss sb sI so so so so}",
                   "name", l2net->name,
                   "ident", l2net->if_ident,
                   "type", oonf_layer2_net_get_type_name(l2net->if_type),
                   "dlep", l2net->if_dlep,
                   "last_seen", -oonf_clock_get_relative(l2net->last_seen),
                   "local_peers", j_ips,
                   "data", j_netdata,
                   "neighbor_defaults", j_neighdata,
                   "neighbors", j_neighs
          ))) {
    return __LINE__;
  }

  avl_for_each_element(&l2net->local_peer_ips, l2peer, _net_node) {
    if(json_array_append_new(
        j_ips, json_pack_ex(error, sizeof(*error),
                            "{ss ss}",
                            "ip", netaddr_to_string(&nbuf, &l2peer->ip),
                            "origin", l2peer->origin->name
              ))) {
      return __LINE__;
    }
  }

  for (netidx = 0; netidx < OONF_LAYER2_NET_COUNT; netidx++) {
    l2data = &l2net->data[netidx];
    l2meta = oonf_layer2_net_metadata_get(netidx);
    if ((result =_add_data_object(error, j_netdata, l2data, l2meta))) {
      return result;
    }
  }

  for (neighidx = 0; neighidx < OONF_LAYER2_NEIGH_COUNT; neighidx++) {
    l2data = &l2net->neighdata[neighidx];
    l2meta = oonf_layer2_neigh_metadata_get(neighidx);
    if ((result =_add_data_object(error, j_neighdata, l2data, l2meta))) {
      return result;
    }
  }

  avl_for_each_element(&l2net->neighbors, l2neigh, _node) {
    if ((result = _export_l2neigh(error, j_neighs, l2neigh))) {
      return result;
    }
  }
  return 0;
}

static int
_export_root(json_error_t *error, json_t *root) {
  struct oonf_layer2_net *l2net;
  json_t *j_nets;
  int result;

  if (!(j_nets = json_array()))
    return __LINE__;

  if (json_object_set_new(root, "interfaces", j_nets))
    return __LINE__;

  avl_for_each_element(oonf_layer2_get_net_tree(), l2net, _node) {
    if ((result = _export_l2net(error, j_nets, l2net))) {
      return result;
    }
  }
  return 0;
}

static int
_cb_dump(const char *buffer, size_t size, void *data) {
  struct oonf_telnet_data *con = data;
  return abuf_memcpy(con->out, buffer, size);
}

