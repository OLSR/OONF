
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
#include <oonf/oonf.h>
#include <oonf/libcommon/json.h>

#include <oonf/libcore/oonf_logging.h>
#include <oonf/libcore/oonf_subsystem.h>
#include <oonf/base/oonf_clock.h>
#include <oonf/base/oonf_telnet.h>

#include <oonf/nhdp/nhdp/nhdp.h>
#include <oonf/nhdp/nhdp/nhdp_db.h>
#include <oonf/nhdp/nhdp/nhdp_domain.h>
#include <oonf/nhdp/nhdp/nhdp_interfaces.h>
#include <oonf/olsrv2/olsrv2/olsrv2.h>
#include <oonf/olsrv2/olsrv2/olsrv2_lan.h>
#include <oonf/olsrv2/olsrv2/olsrv2_originator.h>
#include <oonf/olsrv2/olsrv2/olsrv2_routing.h>
#include <oonf/olsrv2/olsrv2/olsrv2_tc.h>

#include <oonf/olsrv2/netjsoninfo/netjsoninfo.h>

/* definitions */
#define LOG_NETJSONINFO olsrv2_netjsoninfo.logging

/*! name of filter command */
#define JSON_NAME_FILTER "filter"

/*! name of graph command/json-object */
#define JSON_NAME_GRAPH "graph"

/*! name of route command/json-object */
#define JSON_NAME_ROUTE "route"

/*! name of domain command/json-object */
#define JSON_NAME_DOMAIN "domain"

/*! name of domain command/json-object */
#define JSON_NAME_ID "id"

/*! Text buffer for a domain id string */
struct domain_id_str {
  /*! string buffer */
  char buf[16];
};

/*! Text buffer for a node id string */
struct _node_id_str {
  /*! string buffer */
  char buf[256];
};

/*! types of nodes known to olsrv2 netjson graph */
enum netjson_node_type
{
  /*! the local node itself */
  NETJSON_NODE_LOCAL,

  /*! attached network prefix of the local node */
  NETJSON_NODE_LAN,

  /*! a remote OLSRv2 router */
  NETJSON_NODE_ROUTERS,

  /*! attached network prefix of a remote router */
  NETJSON_NODE_ATTACHED,
};

/*! types of edges known to olsrv2 netjson graph */
enum netjson_edge_type
{
  /*! outgoing edge of the local router */
  NETJSON_EDGE_LOCAL,

  /*! edge to attached prefix of the local router */
  NETJSON_EDGE_LAN,

  /*! edge from or between remote routers */
  NETJSON_EDGE_ROUTERS,

  /*! edge to attached prefix of a remote router */
  NETJSON_EDGE_ATTACHED,
};

/* prototypes */
static int _init(void);
static void _cleanup(void);

static void _print_graph(struct json_session *session, struct nhdp_domain *domain, int af_type);
static void _create_graph_json(struct json_session *session, const char *filter);
static void _print_routing_tree(struct json_session *session, struct nhdp_domain *domain, int af_type);
static void _create_route_json(struct json_session *session, const char *filter);
static void _create_domain_json(struct json_session *session);
static void _create_id_json(struct json_session *session);
static void _create_error_json(struct json_session *session, const char *message, const char *parameter);
static enum oonf_telnet_result _cb_netjsoninfo(struct oonf_telnet_data *con);
static void _print_json_string(struct json_session *session, const char *key, const char *value);
static void _print_json_number(struct json_session *session, const char *key, uint64_t value);
static void _print_json_netaddr(struct json_session *session, const char *key, const struct netaddr *addr);

/* telnet command of this plugin */
static struct oonf_telnet_command _telnet_commands[] = {
  TELNET_CMD(OONF_NETJSONINFO_SUBSYSTEM, _cb_netjsoninfo,
    "The command has three main commands (route, graph, domain) and a"
    " 'filter' prefix for route/graph. You can use any combination of the"
    " three main commands (space separated) to generate a NetworkCollection"
    " with the information of the main commands for all known domains.\n"
    "> netjsoninfo route graph\n"
    "The filter prefix use an id (which can be queried by 'domain') to output"
    " a single domain of route/graph without the NetworkCollection object"
    " around it. The domain_id's are ipv4_<domain_number> and ipv6_<domain_number>.\n"
    "> netjsoninfo filter route ipv4_0\n"
    "Netjsoninfo 'id' returns a list of router/prefix id's to the corresponding\n"
    "IPs/prefixes\n"),
};

/* plugin declaration */
static const char *_dependencies[] = {
  OONF_NHDP_SUBSYSTEM,
  OONF_OLSRV2_SUBSYSTEM,
  OONF_TELNET_SUBSYSTEM,
};
static struct oonf_subsystem olsrv2_netjsoninfo = {
  .name = OONF_NETJSONINFO_SUBSYSTEM,
  .dependencies = _dependencies,
  .dependencies_count = ARRAYSIZE(_dependencies),
  .descr = "OLSRv2 JSON for networks generator plugin",
  .author = "Henning Rogge",
  .init = _init,
  .cleanup = _cleanup,
};
DECLARE_OONF_PLUGIN(olsrv2_netjsoninfo);

/**
 * Initialize plugin
 * @return always returns 0
 */
static int
_init(void) {
  oonf_telnet_add(&_telnet_commands[0]);
  return 0;
}

/**
 * Cleanup plugin
 */
static void
_cleanup(void) {
  oonf_telnet_remove(&_telnet_commands[0]);
}

/**
 * @param af_type address family type
 * @return originator of the other type (IPv4 for IPv6)
 */
static int
_get_other_af_type(int af_type) {
  switch (af_type) {
    case AF_INET:
      return AF_INET6;
      break;
    case AF_INET6:
      return AF_INET;
      break;
    default:
      return 0;
  }
}

/**
 * Create a domain id string
 * @param buf output buffer
 * @param domain nhdp domain
 * @param af_type address family type
 * @return pointer to output buffer
 */
static const char *
_create_domain_id(struct domain_id_str *buf, struct nhdp_domain *domain, int af_type) {
  snprintf(buf->buf, sizeof(*buf), "%s_%u", af_type == AF_INET ? "ipv4" : "ipv6", domain->ext);
  return buf->buf;
}

/**
 * Create a node id string
 * @param buf output buffer
 * @param originator originator address
 * @param addr secondary address, might be NULL
 * @return pointer to output buffer
 */
static const char *
_get_node_id(struct _node_id_str *buf, const struct netaddr *originator, const struct netaddr *addr) {
  struct netaddr_str nbuf1, nbuf2;

  netaddr_to_string(&nbuf1, originator);

  if (!addr) {
    snprintf(buf->buf, sizeof(*buf), "id_%s", nbuf1.buf);
  }
  else {
    netaddr_to_string(&nbuf2, addr);

    snprintf(buf->buf, sizeof(*buf), "id_%s_%s", nbuf1.buf, nbuf2.buf);
  }
  return buf->buf;
}

/**
 * Create a node id string for the local router
 * @param buf output buffer
 * @param af_family address family
 * @return pointer to output buffer
 */
static const char *
_get_node_id_me(struct _node_id_str *buf, int af_family) {
  return _get_node_id(buf, olsrv2_originator_get(af_family), NULL);
}

/**
 * Create a node id string for a remote router
 * @param buf output buffer
 * @param node tc node
 * @return pointer to output buffer
 */
static const char *
_get_tc_node_id(struct _node_id_str *buf, const struct olsrv2_tc_node *node) {
  return _get_node_id(buf, &node->target.prefix.dst, NULL);
}

/**
 * Create a node id for a remote endpoint (attached prefix)
 * @param buf output buffer
 * @param attachment tc attachment
 * @return pointer to output buffer
 */
static const char *
_get_tc_endpoint_id(struct _node_id_str *buf, const struct olsrv2_tc_attachment *attachment) {
  return _get_node_id(buf, &attachment->src->target.prefix.dst, &attachment->dst->target.prefix.dst);
}

/**
 * Create a node id for a locally attached network
 * @param buf output buffer
 * @param lan locally attached network
 * @return pointer to output buffer
 */
static const char *
_get_tc_lan_id(struct _node_id_str *buf, const struct olsrv2_lan_entry *lan) {
  int af_family;

  af_family = netaddr_get_address_family(&lan->prefix.dst);
  return _get_node_id(buf, olsrv2_originator_get(af_family), &lan->prefix.dst);
}

/**
 * Create a node id for a NHDP neighbor
 * @param buf output buffer
 * @param neigh NHDP neighbor
 * @return pointer to output buffer
 */
static const char *
_get_nhdp_neighbor_id(struct _node_id_str *buf, const struct nhdp_neighbor *neigh) {
  return _get_node_id(buf, &neigh->originator, NULL);
}

/**
 * Print the JSON output for a graph node
 * @param session json session
 * @param id node address
 * @param originator node originator address
 * @param dualstack node dualstack originator address
 * @param type netjson node type
 */
static void
_print_graph_node(struct json_session *session, const struct _node_id_str *id, const char *label,
  const struct netaddr *originator, const struct netaddr *dualstack, enum netjson_node_type type) {
  struct _node_id_str originator_id, dualstack_id;

  ;

  json_start_object(session, NULL);

  _print_json_string(session, "id", id->buf);
  _print_json_string(session, "label", label);

  json_start_object(session, "properties");
  if (originator) {
    _print_json_string(session, "router_id", _get_node_id(&originator_id, originator, NULL));
    _print_json_netaddr(session, "router_addr", originator);
  }
  if (dualstack) {
    _print_json_string(session, "dualstack_id", _get_node_id(&dualstack_id, dualstack, NULL));
    _print_json_netaddr(session, "dualstack_addr", dualstack);
  }

  switch (type) {
    case NETJSON_NODE_LOCAL:
      _print_json_string(session, "type", "local");
      break;
    case NETJSON_NODE_LAN:
      _print_json_string(session, "type", "lan");
      break;
    case NETJSON_NODE_ROUTERS:
      _print_json_string(session, "type", "node");
      break;
    case NETJSON_NODE_ATTACHED:
      _print_json_string(session, "type", "attached");
      break;
    default:
      _print_json_string(session, "type", "unknown");
      break;
  }
  json_end_object(session);

  json_end_object(session);
}

/**
 * Print the JSON node element for the local node
 * @param session json session
 * @param af_family address family
 */
static void
_print_graph_node_me(struct json_session *session, int af_family) {
  struct _node_id_str ebuf1;
  struct netaddr_str nbuf1;
  const struct netaddr *dualstack;

  _get_node_id_me(&ebuf1, af_family);
  netaddr_to_string(&nbuf1, olsrv2_originator_get(af_family));

  dualstack = olsrv2_originator_get(_get_other_af_type(af_family));
  _print_graph_node(session, &ebuf1, nbuf1.buf, olsrv2_originator_get(af_family), dualstack, NETJSON_NODE_LOCAL);
}

/**
 * Print the JSON node element for a tc node
 * @param session json session
 * @param node tc node
 */
static void
_print_graph_node_tc(struct json_session *session, const struct olsrv2_tc_node *node) {
  const struct netaddr *dualstack;
  struct _node_id_str ebuf;
  struct netaddr_str nbuf1;
  struct nhdp_neighbor *neigh;

  _get_tc_node_id(&ebuf, node);
  netaddr_to_string(&nbuf1, &node->target.prefix.dst);

  dualstack = NULL;
  neigh = nhdp_db_neighbor_get_by_originator(&node->target.prefix.dst);
  if (neigh && neigh->dualstack_partner) {
    dualstack = &neigh->dualstack_partner->originator;
  }
  _print_graph_node(session, &ebuf, nbuf1.buf, &node->target.prefix.dst, dualstack, NETJSON_NODE_ROUTERS);
}

/**
 * Print the JSON node element for a tc attachment
 * @param session json session
 * @param attachment tc attachment
 */
static void
_print_graph_node_attached(struct json_session *session, const struct olsrv2_tc_attachment *attachment) {
  struct _node_id_str ebuf;
  struct netaddr_str nbuf1, nbuf2;

  char labelbuf[256];

  _get_tc_endpoint_id(&ebuf, attachment);
  netaddr_to_string(&nbuf1, &attachment->src->target.prefix.dst);
  netaddr_to_string(&nbuf2, &attachment->dst->target.prefix.dst);

  snprintf(labelbuf, sizeof(labelbuf), "%s - %s", nbuf1.buf, nbuf2.buf);

  _print_graph_node(session, &ebuf, labelbuf, &attachment->src->target.prefix.dst, NULL, NETJSON_NODE_ATTACHED);
}

/**
 * Print the JSON node element for a locally attached network
 * @param session json session
 * @param lan locally attached network
 */
static void
_print_graph_node_lan(struct json_session *session, const struct olsrv2_lan_entry *lan) {
  const struct netaddr *originator;
  struct netaddr_str nbuf1, nbuf2;
  struct _node_id_str ebuf;
  int af_type;

  char labelbuf[256];

  af_type = netaddr_get_address_family(&lan->prefix.dst);
  originator = olsrv2_originator_get(af_type);

  _get_tc_lan_id(&ebuf, lan);
  netaddr_to_string(&nbuf1, originator);
  netaddr_to_string(&nbuf2, &lan->prefix.dst);

  snprintf(labelbuf, sizeof(labelbuf), "%s - %s", nbuf1.buf, nbuf2.buf);

  _print_graph_node(session, &ebuf, labelbuf, originator, NULL, NETJSON_NODE_LAN);
}

/**
 * Print the NHDP links for a JSON link element.
 * @param session json session
 * @param domain nhdp domain
 * @param neigh nhdp neighbor
 * @param outgoing neighbor link is on outgoing dijkstra tree
 */
static void
_print_edge_links(
  struct json_session *session, struct nhdp_domain *domain, struct nhdp_neighbor *neigh, bool outgoing) {
  struct nhdp_link *lnk;
  struct nhdp_link *best_link;
  struct nhdp_metric_str mbuf;
  int32_t cost;
  int af_type;

  af_type = netaddr_get_address_family(&neigh->originator);

  best_link = nhdp_domain_get_neighbordata(domain, neigh)->best_out_link;

  json_start_array(session, "links");

  list_for_each_element(&neigh->_links, lnk, _neigh_node) {
    if (netaddr_get_address_family(&lnk->if_addr) != af_type) {
      continue;
    }

    json_start_object(session, NULL);

    _print_json_string(session, "interface", nhdp_interface_get_name(lnk->local_if));

    _print_json_netaddr(session, "source_addr", nhdp_interface_get_socket_address(lnk->local_if, af_type));
    _print_json_netaddr(session, "target_addr", &lnk->if_addr);

    cost = nhdp_domain_get_linkdata(domain, lnk)->metric.out;
    _print_json_number(session, "cost", cost);
    _print_json_string(session, "cost_text", nhdp_domain_get_link_metric_value(&mbuf, domain, cost));

    cost = nhdp_domain_get_linkdata(domain, lnk)->metric.in;
    _print_json_number(session, "in_cost", cost);
    _print_json_string(session, "in_text", nhdp_domain_get_link_metric_value(&mbuf, domain, cost));

    _print_json_string(session, "outgoing_tree", json_getbool(outgoing && best_link == lnk));

    json_end_object(session);
  }

  json_end_array(session);
}

/**
 * Print a JSON graph edge
 * @param session json session
 * @param domain nhdp domain
 * @param src source id
 * @param dst destination id
 * @param src_addr source IP address
 * @param dst_addr destination IP address
 * @param out outgoing metric
 * @param in incoming metric, 0 for no metric
 * @param hopcount outgoing hopcount, 0 for no hopcount
 * @param outgoing_tree true if part of outgoing tree
 * @param type edge type
 * @param neigh reference to NHDP neighbor of edge,
 *   NULL if no direct neighbor edge
 */
static void
_print_graph_edge(struct json_session *session, struct nhdp_domain *domain, const struct _node_id_str *src,
  const struct _node_id_str *dst, const struct netaddr *src_addr, const struct netaddr *dst_addr, uint32_t out,
  uint32_t in, uint8_t hopcount, bool outgoing_tree, enum netjson_edge_type type, struct nhdp_neighbor *neigh) {
  struct nhdp_metric_str mbuf;

  if (out > RFC7181_METRIC_MAX) {
    return;
  }

  json_start_object(session, NULL);
  _print_json_string(session, "source", src->buf);
  _print_json_string(session, "target", dst->buf);

  _print_json_number(session, "cost", out);
  _print_json_string(session, "cost_text", nhdp_domain_get_link_metric_value(&mbuf, domain, out));

  json_start_object(session, "properties");
  if (in >= RFC7181_METRIC_MIN && in <= RFC7181_METRIC_MAX) {
    _print_json_number(session, "in_cost", in);
    _print_json_string(session, "in_text", nhdp_domain_get_link_metric_value(&mbuf, domain, in));
  }
  _print_json_string(session, "outgoing_tree", json_getbool(outgoing_tree));

  if (src_addr) {
    _print_json_netaddr(session, "source_addr", src_addr);
  }
  if (dst_addr) {
    _print_json_netaddr(session, "target_addr", dst_addr);
  }
  if (hopcount) {
    _print_json_number(session, "hopcount", hopcount);
  }

  switch (type) {
    case NETJSON_EDGE_LOCAL:
      _print_json_string(session, "type", "local");
      break;
    case NETJSON_EDGE_LAN:
      _print_json_string(session, "type", "lan");
      break;
    case NETJSON_EDGE_ROUTERS:
      _print_json_string(session, "type", "node");
      break;
    case NETJSON_EDGE_ATTACHED:
      _print_json_string(session, "type", "attached");
      break;
    default:
      _print_json_string(session, "type", "unknown");
      break;
  }

  if (neigh) {
    _print_edge_links(session, domain, neigh, outgoing_tree);
  }
  json_end_object(session);
  json_end_object(session);
}

/**
 * Print the JSON graph object
 * @param session json session
 * @param domain NHDP domain
 * @param af_type address family type
 */
static void
_print_graph(struct json_session *session, struct nhdp_domain *domain, int af_type) {
  struct os_route_key routekey;
  const struct netaddr *originator, *dualstack;
  struct nhdp_neighbor *neigh;
  struct olsrv2_tc_node *node;
  struct olsrv2_tc_edge *edge;
  struct olsrv2_tc_attachment *attached;
  struct olsrv2_lan_entry *lan;
  struct avl_tree *rt_tree;
  struct olsrv2_routing_entry *rt_entry;
  struct domain_id_str dbuf;
  struct _node_id_str node_id1, node_id2;
  int other_af;

  bool outgoing;

  originator = olsrv2_originator_get(af_type);
  if (netaddr_is_unspec(originator)) {
    return;
  }

  /* get "other" originator */
  other_af = _get_other_af_type(af_type);

  /* get dualstack originator */
  dualstack = olsrv2_originator_get(AF_INET6);

  json_start_object(session, NULL);

  _print_json_string(session, "type", "NetworkGraph");
  _print_json_string(session, "protocol", "olsrv2");
  _print_json_string(session, "version", oonf_log_get_libdata()->version);
  _print_json_string(session, "revision", oonf_log_get_libdata()->git_commit);

  _print_json_string(session, "router_id", _get_node_id_me(&node_id1, af_type));

  _print_json_string(session, "metric", domain->metric->name);
  _print_json_string(session, "topology_id", _create_domain_id(&dbuf, domain, af_type));

  json_start_object(session, "properties");
  _print_json_netaddr(session, "router_addr", originator);
  if (dualstack) {
    _print_json_string(session, "dualstack_id", _get_node_id_me(&node_id1, other_af));
    _print_json_string(session, "dualstack_topology", _create_domain_id(&dbuf, domain, other_af));
    _print_json_netaddr(session, "dualstack_addr", dualstack);
  }
  json_end_object(session);

  json_start_array(session, "nodes");

  /* local node */
  _print_graph_node_me(session, af_type);

  /* locally attached networks */
  avl_for_each_element(olsrv2_lan_get_tree(), lan, _node) {
    if (netaddr_get_address_family(&lan->prefix.dst) == af_type && olsrv2_lan_get_domaindata(domain, lan)->active) {
      _print_graph_node_lan(session, lan);
    }
  }

  /* originators of all other nodes */
  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    if (netaddr_get_address_family(&node->target.prefix.dst) == af_type) {
      if (netaddr_cmp(&node->target.prefix.dst, originator) == 0) {
        continue;
      }

      _print_graph_node_tc(session, node);

      /* attached networks */
      avl_for_each_element(&node->_attached_networks, attached, _src_node) {
        _print_graph_node_attached(session, attached);
      }
    }
  }
  json_end_array(session);

  json_start_array(session, "links");

  rt_tree = olsrv2_routing_get_tree(domain);

  /* print local links to neighbors */
  _get_node_id_me(&node_id1, af_type);

  avl_for_each_element(nhdp_db_get_neigh_originator_tree(), neigh, _originator_node) {
    if (netaddr_get_address_family(&neigh->originator) == af_type && neigh->symmetric > 0) {
      os_routing_init_sourcespec_prefix(&routekey, &neigh->originator);

      rt_entry = avl_find_element(rt_tree, &routekey, rt_entry, _node);
      outgoing = rt_entry != NULL && netaddr_cmp(&rt_entry->last_originator, originator) == 0;

      _get_nhdp_neighbor_id(&node_id2, neigh);

      _print_graph_edge(session, domain, &node_id1, &node_id2, originator, &neigh->originator,
        nhdp_domain_get_neighbordata(domain, neigh)->metric.out, nhdp_domain_get_neighbordata(domain, neigh)->metric.in,
        0, outgoing, NETJSON_EDGE_LOCAL, neigh);

      _print_graph_edge(session, domain, &node_id2, &node_id1, &neigh->originator, originator,
        nhdp_domain_get_neighbordata(domain, neigh)->metric.in, nhdp_domain_get_neighbordata(domain, neigh)->metric.out,
        0, false, NETJSON_EDGE_ROUTERS, NULL);
    }
  }

  /* print local endpoints */
  avl_for_each_element(olsrv2_lan_get_tree(), lan, _node) {
    if (netaddr_get_address_family(&lan->prefix.dst) == af_type && olsrv2_lan_get_domaindata(domain, lan)->active) {
      rt_entry = avl_find_element(rt_tree, &lan->prefix, rt_entry, _node);
      outgoing = rt_entry == NULL;

      _get_tc_lan_id(&node_id2, lan);

      _print_graph_edge(session, domain, &node_id1, &node_id2, originator, &lan->prefix.dst,
        olsrv2_lan_get_domaindata(domain, lan)->outgoing_metric, 0, olsrv2_lan_get_domaindata(domain, lan)->distance,
        outgoing, NETJSON_EDGE_LAN, NULL);
    }
  }

  /* print remote node links to neighbors */
  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    if (netaddr_get_address_family(&node->target.prefix.dst) == af_type) {
      _get_tc_node_id(&node_id1, node);

      avl_for_each_element(&node->_edges, edge, _node) {
        if (!edge->virtual) {
          if (netaddr_cmp(&edge->dst->target.prefix.dst, originator) == 0) {
            /* we already have this information from NHDP */
            continue;
          }

          rt_entry = avl_find_element(rt_tree, &edge->dst->target.prefix, rt_entry, _node);
          outgoing = rt_entry != NULL && netaddr_cmp(&rt_entry->last_originator, &node->target.prefix.dst) == 0;

          _get_tc_node_id(&node_id2, edge->dst);

          _print_graph_edge(session, domain, &node_id1, &node_id2, &node->target.prefix.dst,
            &edge->dst->target.prefix.dst, edge->cost[domain->index], edge->inverse->cost[domain->index], 0, outgoing,
            NETJSON_EDGE_ROUTERS, NULL);
        }
      }
    }
  }

  /* print remote nodes neighbors */
  avl_for_each_element(olsrv2_tc_get_tree(), node, _originator_node) {
    if (netaddr_get_address_family(&node->target.prefix.dst) == af_type) {
      _get_tc_node_id(&node_id1, node);

      avl_for_each_element(&node->_attached_networks, attached, _src_node) {
        rt_entry = avl_find_element(rt_tree, &attached->dst->target.prefix, rt_entry, _node);
        outgoing = rt_entry != NULL && netaddr_cmp(&rt_entry->originator, &node->target.prefix.dst) == 0;

        _get_tc_endpoint_id(&node_id2, attached);

        _print_graph_edge(session, domain, &node_id1, &node_id2, &node->target.prefix.dst,
          &attached->dst->target.prefix.dst, attached->cost[domain->index], 0, attached->distance[domain->index],
          outgoing, NETJSON_EDGE_ATTACHED, NULL);
      }
    }
  }
  json_end_array(session);

  json_end_object(session);
}

/**
 * Print all JSON graph objects
 * @param session json session
 * @param filter domain filter
 */
static void
_create_graph_json(struct json_session *session, const char *filter) {
  struct nhdp_domain *domain;
  struct domain_id_str dbuf;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (filter == NULL || strcmp(_create_domain_id(&dbuf, domain, AF_INET), filter) == 0) {
      _print_graph(session, domain, AF_INET);
    }
    if (filter == NULL || strcmp(_create_domain_id(&dbuf, domain, AF_INET6), filter) == 0) {
      _print_graph(session, domain, AF_INET6);
    }
  }
}

/**
 * Print the JSON routing tree
 * @param session json session
 * @param domain NHDP domain
 * @param af_type address family
 */
static void
_print_routing_tree(struct json_session *session, struct nhdp_domain *domain, int af_type) {
  struct olsrv2_routing_entry *rtentry;
  const struct netaddr *originator;
  char ibuf[IF_NAMESIZE];
  struct nhdp_metric_str mbuf;
  struct domain_id_str dbuf;
  struct _node_id_str idbuf;

  originator = olsrv2_originator_get(af_type);
  if (netaddr_get_address_family(originator) != af_type) {
    return;
  }

  json_start_object(session, NULL);

  _print_json_string(session, "type", "NetworkRoutes");
  _print_json_string(session, "protocol", "olsrv2");
  _print_json_string(session, "version", oonf_log_get_libdata()->version);
  _print_json_string(session, "revision", oonf_log_get_libdata()->git_commit);

  _get_node_id_me(&idbuf, af_type);
  _print_json_string(session, "router_id", idbuf.buf);
  _print_json_string(session, "metric", domain->metric->name);
  _print_json_string(session, "topology_id", _create_domain_id(&dbuf, domain, af_type));

  json_start_object(session, "properties");
  _print_json_netaddr(session, "router_addr", originator);
  json_end_object(session);

  json_start_array(session, "routes");

  avl_for_each_element(olsrv2_routing_get_tree(domain), rtentry, _node) {
    if (rtentry->route.p.family == af_type) {
      json_start_object(session, NULL);

      _print_json_netaddr(session, "destination", &rtentry->route.p.key.dst);

      if (netaddr_get_prefix_length(&rtentry->route.p.key.src) > 0) {
        _print_json_netaddr(session, "source", &rtentry->route.p.key.src);
      }

      _get_node_id(&idbuf, &rtentry->next_originator, NULL);
      _print_json_netaddr(session, "next", &rtentry->route.p.gw);

      _print_json_string(session, "device", if_indextoname(rtentry->route.p.if_index, ibuf));
      _print_json_number(session, "cost", rtentry->path_cost);
      _print_json_string(
        session, "cost_text", nhdp_domain_get_path_metric_value(&mbuf, domain, rtentry->path_cost, rtentry->path_hops));

      json_start_object(session, "properties");
      if (!netaddr_is_unspec(&rtentry->originator)) {
        _get_node_id(&idbuf, &rtentry->originator, NULL);
        _print_json_string(session, "destination_id", idbuf.buf);
      }
      _print_json_string(session, "next_router_id", idbuf.buf);
      _print_json_netaddr(session, "next_router_addr", &rtentry->next_originator);

      _print_json_number(session, "hops", rtentry->path_hops);

      _get_node_id(&idbuf, &rtentry->last_originator, NULL);
      _print_json_string(session, "last_router_id", idbuf.buf);
      _print_json_netaddr(session, "last_router_addr", &rtentry->last_originator);
      json_end_object(session);

      json_end_object(session);
    }
  }

  json_end_array(session);
  json_end_object(session);
}

/**
 * Print all JSON routes
 * @param session json session
 * @param filter filter value to select domain
 */
static void
_create_route_json(struct json_session *session, const char *filter) {
  struct nhdp_domain *domain;
  struct domain_id_str dbuf;

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (filter == NULL || strcmp(_create_domain_id(&dbuf, domain, AF_INET), filter) == 0) {
      _print_routing_tree(session, domain, AF_INET);
    }
    if (filter == NULL || strcmp(_create_domain_id(&dbuf, domain, AF_INET6), filter) == 0) {
      _print_routing_tree(session, domain, AF_INET6);
    }
  }
}

static void
_create_domain_json(struct json_session *session) {
  const struct netaddr *originator_v4, *originator_v6;
  struct nhdp_domain *domain;
  struct domain_id_str dbuf;
  struct _node_id_str idbuf;

  originator_v4 = olsrv2_originator_get(AF_INET);
  originator_v6 = olsrv2_originator_get(AF_INET6);

  json_start_object(session, NULL);

  _print_json_string(session, "type", "NetworkDomain");
  _print_json_string(session, "protocol", "olsrv2");
  _print_json_string(session, "version", oonf_log_get_libdata()->version);
  _print_json_string(session, "revision", oonf_log_get_libdata()->git_commit);

  json_start_array(session, JSON_NAME_DOMAIN);

  list_for_each_element(nhdp_domain_get_list(), domain, _node) {
    if (!netaddr_is_unspec(originator_v4)) {
      json_start_object(session, NULL);

      _print_json_string(session, "id", _create_domain_id(&dbuf, domain, AF_INET));
      _print_json_number(session, "number", domain->ext);

      _get_node_id_me(&idbuf, AF_INET);
      _print_json_string(session, "router_id", idbuf.buf);
      _print_json_netaddr(session, "router_addr", originator_v4);
      _print_json_string(session, "metric", domain->metric->name);
      _print_json_string(session, "mpr", domain->mpr->name);

      json_end_object(session);
    }

    if (!netaddr_is_unspec(originator_v6)) {
      json_start_object(session, NULL);

      _print_json_string(session, "id", _create_domain_id(&dbuf, domain, AF_INET6));
      _print_json_number(session, "number", domain->ext);

      _get_node_id_me(&idbuf, AF_INET6);
      _print_json_string(session, "router_id", idbuf.buf);
      _print_json_netaddr(session, "router_addr", originator_v6);
      _print_json_string(session, "metric", domain->metric->name);
      _print_json_string(session, "mpr", domain->mpr->name);

      json_end_object(session);
    }
  }

  json_end_array(session);
  json_end_object(session);
}

static void
_create_id_json(struct json_session *session) {
  struct olsrv2_tc_node *tc_node;
  struct olsrv2_tc_attachment *tc_attached;
  struct olsrv2_lan_entry *lan;
  struct nhdp_domain *domain;
  struct _node_id_str node_id_str;
  int af;

  json_start_object(session, NULL);

  _print_json_string(session, "type", "NetworkId");
  _print_json_string(session, "protocol", "olsrv2");
  _print_json_string(session, "version", oonf_log_get_libdata()->version);
  _print_json_string(session, "revision", oonf_log_get_libdata()->git_commit);

  json_start_array(session, "routers");

  /* local router */
  if (olsrv2_originator_get(AF_INET)) {
    json_start_object(session, NULL);
    _print_json_string(session, "router_id", _get_node_id_me(&node_id_str, AF_INET));
    _print_json_netaddr(session, "router_addr", olsrv2_originator_get(AF_INET));
    json_end_object(session);
  }
  if (olsrv2_originator_get(AF_INET6)) {
    json_start_object(session, NULL);
    _print_json_string(session, "router_id", _get_node_id_me(&node_id_str, AF_INET6));
    _print_json_netaddr(session, "router_addr", olsrv2_originator_get(AF_INET6));
    json_end_object(session);
  }

  /* remote routers */
  avl_for_each_element(olsrv2_tc_get_tree(), tc_node, _originator_node) {
    json_start_object(session, NULL);
    _print_json_string(session, "router_id", _get_tc_node_id(&node_id_str, tc_node));
    _print_json_netaddr(session, "router_addr", &tc_node->target.prefix.dst);
    json_end_object(session);
  }
  json_end_array(session);

  json_start_array(session, "attached");
  /* locally attached */
  avl_for_each_element(olsrv2_lan_get_tree(), lan, _node) {
    af = netaddr_get_address_family(&lan->prefix.dst);
    list_for_each_element(nhdp_domain_get_list(), domain, _node) {
      json_start_object(session, NULL);
      _print_json_string(session, "attached_id", _get_tc_lan_id(&node_id_str, lan));
      _print_json_string(session, "router_id", _get_node_id_me(&node_id_str, af));
      _print_json_netaddr(session, "router_addr", olsrv2_originator_get(af));
      _print_json_netaddr(session, "attached_dst", &lan->prefix.dst);
      _print_json_netaddr(session, "attached_src", &lan->prefix.src);
      json_end_object(session);
    }
  }
  /* remote prefixes */
  avl_for_each_element(olsrv2_tc_get_tree(), tc_node, _originator_node) {
    avl_for_each_element(&tc_node->_attached_networks, tc_attached, _src_node) {
      json_start_object(session, NULL);
      _print_json_string(session, "attached_id", _get_tc_endpoint_id(&node_id_str, tc_attached));
      _print_json_string(session, "router_id", _get_tc_node_id(&node_id_str, tc_node));
      _print_json_netaddr(session, "router_addr", &tc_node->target.prefix.dst);
      _print_json_netaddr(session, "attached_dst", &tc_attached->dst->target.prefix.dst);
      _print_json_netaddr(session, "attached_src", &tc_attached->dst->target.prefix.src);
      json_end_object(session);
    }
  }
  json_end_array(session);
  json_end_object(session);
}

/**
 * Print a JSON error
 * @param session json session
 * @param message error message
 * @param parameter error parameter
 */
static void
_create_error_json(struct json_session *session, const char *message, const char *parameter) {
  json_start_object(session, NULL);

  _print_json_string(session, "type", "Error");
  _print_json_string(session, "message", message);
  _print_json_string(session, "parameter", parameter);

  json_end_object(session);
}

static const char *
_handle_netjson_object(struct json_session *session, const char *parameter, bool filter, bool *error) {
  const char *ptr;

  if ((ptr = str_hasnextword(parameter, JSON_NAME_GRAPH))) {
    _create_graph_json(session, filter ? ptr : NULL);
  }
  else if ((ptr = str_hasnextword(parameter, JSON_NAME_ROUTE))) {
    _create_route_json(session, filter ? ptr : NULL);
  }
  else if (!filter && (ptr = str_hasnextword(parameter, JSON_NAME_DOMAIN))) {
    _create_domain_json(session);
  }
  else if (!filter && (ptr = str_hasnextword(parameter, JSON_NAME_ID))) {
    _create_id_json(session);
  }
  else {
    ptr = str_skipnextword(parameter);
    *error = true;
  }
  return ptr;
}

static void
_handle_filter(struct json_session *session, const char *parameter) {
  bool error = false;

  _handle_netjson_object(session, parameter, true, &error);
  if (error) {
    _create_error_json(session, "Could not parse sub-command for netjsoninfo", parameter);
  }
}

static void
_handle_collection(struct json_session *session, const char *parameter) {
  const char *next;
  bool error;

  json_start_object(session, NULL);
  _print_json_string(session, "type", "NetworkCollection");
  json_start_array(session, "collection");

  error = 0;
  next = parameter;
  while (next && *next) {
    next = _handle_netjson_object(session, next, false, &error);
  }

  if (error) {
    _create_error_json(session, "Could not parse sub-command for netjsoninfo", parameter);
  }

  json_end_array(session);
  json_end_object(session);
}

/**
 * Callback for netjsoninfo telnet command
 * @param con telnet connection
 * @return active or internal_error
 */
static enum oonf_telnet_result
_cb_netjsoninfo(struct oonf_telnet_data *con) {
  struct json_session session;
  struct autobuf out;
  const char *ptr, *next;

  if (abuf_init(&out)) {
    return TELNET_RESULT_INTERNAL_ERROR;
  }

  json_init_session(&session, &out);

  next = con->parameter;
  if (next && *next) {
    if ((ptr = str_hasnextword(next, JSON_NAME_FILTER))) {
      _handle_filter(&session, ptr);
    }
    else {
      _handle_collection(&session, next);
    }
  }

  /* copy output into telnet buffer */
  abuf_memcpy(con->out, abuf_getptr(&out), abuf_getlen(&out));
  abuf_free(&out);
  return TELNET_RESULT_ACTIVE;
}

/**
 * Helper to print a json string
 * @param session json session
 * @param key json key
 * @param value json string value
 */
static void
_print_json_string(struct json_session *session, const char *key, const char *value) {
  json_print(session, key, true, value);
}

/**
 * Helper to print a json number
 * @param session json session
 * @param key json key
 * @param value number
 */
static void
_print_json_number(struct json_session *session, const char *key, uint64_t value) {
  char buffer[21];

  snprintf(buffer, sizeof(buffer), "%" PRIu64, value);
  json_print(session, key, false, buffer);
}

/**
 * Helper function to print a json netaddr object
 * @param session json session
 * @param key json key
 * @param addr address
 */
static void
_print_json_netaddr(struct json_session *session, const char *key, const struct netaddr *addr) {
  struct netaddr_str nbuf;

  json_print(session, key, true, netaddr_to_string(&nbuf, addr));
}
